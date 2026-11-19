"use strict";
/* Operator History: read-only jobs with authenticated, bounded cancel requests. */
(() => {
  const $ = (id) => document.getElementById(id);
  const state = {
    rows: new Map(), pending: new Map(), selected: null, detail: null,
    page: 1, pageCount: 1, pageSize: 15, preferredPageSize: "auto", filteredTotal: 0,
    changesCursor: "", busy: false, filters: {},
    outputCursor: 0, output: { stdout: "", stderr: "" }, decoders: {},
    outputGeneration: 0, loadingOutputGeneration: null,
    outputFullyLoaded: false, outputLoadError: null,
    totals: null, summaryFetchedAt: 0, relativeTime: false, listGeneration: 0,
    requestJson: false, responseJson: false, privilegedOnly: false,
    cancelling: new Set(), readiness: null
  };
  const historyTable = $("history-table");
  const storyMaxChars = Number(historyTable.dataset.storyIdMaxChars || 16);
  const storyTruncateFrom = historyTable.dataset.storyIdTruncateFrom || "end";
  historyTable.style.setProperty("--story-id-column-width", (storyMaxChars + 3) + "ch");
  const tableStoryId = (id) => {
    if (!id) return "—";
    const chars = Array.from(id);
    if (chars.length <= storyMaxChars) return id;
    if (storyMaxChars === 1) return "…";
    return storyTruncateFrom === "start"
      ? "…" + chars.slice(-(storyMaxChars - 1)).join("")
      : chars.slice(0, storyMaxChars - 1).join("") + "…";
  };
  const rowBody = $("job-rows");
  const listWrap = $("list-wrap");
  const tooltip = $("command-tooltip");
  const tooltipText = $("command-tooltip-text");
  let tooltipTarget = null, tooltipTimer = null, tooltipGeneration = 0;
  function hideCommandPreview() {
    clearTimeout(tooltipTimer);
    tooltipGeneration++;
    if (tooltipTarget) tooltipTarget.removeAttribute("aria-describedby");
    tooltipTarget = null;
    tooltip.hidden = true;
  }
  function previewCommand(jobId, cell) {
    hideCommandPreview();
    tooltipTarget = cell;
    const generation = tooltipGeneration;
    tooltipTimer = setTimeout(async () => {
      try {
        // The list contains only a bounded first-line preview. Read the existing
        // authenticated detail endpoint on demand, never copy full commands into lists.
        const detail = state.detail && state.detail.id === jobId
          ? state.detail : (await api("/console/api/jobs/" + escaped(jobId))).job;
        if (generation !== tooltipGeneration || !cell.isConnected) return;
        const command = detail.record_kind === "file"
          ? (detail.command_preview || "File operation") :
          (detail.terminal_command || "Original request not recorded for this older job.");
        tooltipText.textContent = command.split(/\r?\n/).slice(0, 15)
          .map((line, index) => String(index + 1).padStart(2) + "  " + line).join("\n");
        tooltip.hidden = false;
        const rect = cell.getBoundingClientRect();
        const width = tooltip.offsetWidth, height = tooltip.offsetHeight;
        tooltip.style.left = Math.max(12, Math.min(rect.left, window.innerWidth - width - 12)) + "px";
        const below = rect.bottom + 8;
        const above = rect.top - height - 8;
        tooltip.style.top = (below + height < window.innerHeight - 12 ? below
          : above > 12 ? above : Math.max(12, window.innerHeight - height - 12)) + "px";
        cell.setAttribute("aria-describedby", "command-tooltip");
      } catch (_) {
        if (generation === tooltipGeneration) hideCommandPreview();
      }
    }, 300);
  }
  const formatWhen = (date) => date ? new Date(date).toLocaleString() : "—";
  const formatRelative = (date) => {
    if (!date) return "—";
    const timestamp = Date.parse(date);
    if (!Number.isFinite(timestamp)) return "—";
    const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
    if (seconds < 60) return seconds + "s ago";
    if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
    if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
    return Math.floor(seconds / 86400) + "d ago";
  };
  const formatTableTime = (date) => state.relativeTime ? formatRelative(date) : formatWhen(date);
  const statusLabel = (status) => {
    const label = (status || "unknown").replaceAll("_", " ");
    return label[0].toUpperCase() + label.slice(1);
  };
  const duration = (seconds) => {
    if (seconds == null || !Number.isFinite(Number(seconds))) return "—";
    const value = Number(seconds);
    return value >= 60 ? Math.floor(value / 60) + "m " + Math.round(value % 60) + "s"
      : value < 1 ? value.toFixed(1) + "s" : Math.round(value) + "s";
  };
  const modeName = (mode) => mode === "file" ? "File" : mode === "batch" ? "Batch" :
    mode === "sync" ? "Sync" : "Async";
  const asText = (value) => value === undefined || value === null ? "—" : String(value);
  const make = (tag, value, className) => {
    const element = document.createElement(tag);
    if (value !== undefined) element.textContent = asText(value);
    if (className) element.className = className;
    return element;
  };
  const rootShield = () => {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    svg.classList.add("root-shield");
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z");
    svg.append(path);
    return svg;
  };
  const escaped = (value) => encodeURIComponent(value);
  const remember = () => {
    // Preserve the operator's input verbatim (e.g. "191"), not its API normalization.
    try { localStorage.setItem("ssh-mcp-console-filters", JSON.stringify(
      { ...Object.fromEntries(new FormData($("filters")).entries()),
        privileged: state.privilegedOnly ? "true" : "" }
    )); } catch (_) {}
  };
  const currentFilters = () => {
    const data = Object.fromEntries(new FormData($("filters")).entries());
    if (state.privilegedOnly) data.privileged = "true";
    data.conversation_id = String(data.conversation_id || "").trim();
    const story = String(data.story_id || "").trim();
    data.story_id = story;
    if (/^[A-Za-z][A-Za-z0-9]{1,12}-[1-9][0-9]*$/.test(story))
      data.story_id = story.toUpperCase();
    return Object.fromEntries(Object.entries(data).filter(([, value]) => Boolean(value)));
  };
  const matches = (job) => {
    const f = state.filters;
    if (f.privileged === "true" && (job.record_kind === "file" || job.privileged !== true))
      return false;
    if (f.host && job.server !== f.host) return false;
    if (f.story_id) {
      const jobStory = String(job.story_id || "");
      if (/^[0-9]{1,9}$/.test(f.story_id)) {
        if (jobStory !== f.story_id && !jobStory.endsWith("-" + String(Number(f.story_id))))
          return false;
      } else if (/^[A-Za-z][A-Za-z0-9]{1,12}-[1-9][0-9]*$/.test(f.story_id)
        ? !/^[A-Za-z][A-Za-z0-9]{1,12}-[1-9][0-9]*$/.test(jobStory)
          || jobStory.toUpperCase() !== f.story_id : jobStory !== f.story_id) return false;
    }
    if (f.conversation_id && job.conversation_id !== f.conversation_id) return false;
    if (f.status && job.status !== f.status) return false;
    if (f.mode && job.mode !== f.mode) return false;
    if (f.command && ![job.command, job.command_preview].some((value) =>
      (value || "").toLowerCase().includes(f.command.toLowerCase()))) return false;
    const windows = { "1h": 3600, "8h": 28800, "24h": 86400,
                      "7d": 604800, "30d": 2592000 };
    if (windows[f.time_range] && job.created_at &&
        Date.parse(job.created_at) < Date.now() - windows[f.time_range] * 1000) return false;
    return true;
  };
  async function api(path) {
    const response = await fetch(path, { credentials: "same-origin", cache: "no-store" });
    if (response.status === 401) {
      location.assign("/console/login");
      throw new Error("Viewer session expired");
    }
    if (!response.ok) throw new Error("History API returned HTTP " + response.status);
    return response.json();
  }
  function setConnection(connected) {
    const degraded = connected && Number(state.readiness?.degraded_count || 0) > 0;
    const button = $("connection");
    button.textContent = !connected ? "Disconnected" : degraded ? "Degraded" : "Connected";
    button.classList.toggle("offline", !connected);
    button.classList.toggle("degraded", degraded);
    $("readiness-summary").textContent = !connected ? "Console disconnected" :
      state.readiness ? state.readiness.degraded_count + " degraded host(s)" : "Host readiness unavailable";
    const table = document.createElement("table");
    const header = table.insertRow();
    for (const caption of ["Host", "SSH", "Sudo", "Last check", "Last SSH success", "Last sudo success", "Reason"]) {
      const th = document.createElement("th");
      th.textContent = caption;
      header.append(th);
    }
    const time = (value) => value ? new Date(value).toLocaleString() : "—";
    for (const [alias, host] of Object.entries(state.readiness?.hosts || {})) {
      const row = table.insertRow();
      const values = [
        alias,
        host.status !== "active" ? "Offline" : host.ssh_reason ? "Recent failure · still eligible" : "Active",
        !host.sudo_configured ? "N/A" : host.sudo_ready ? "Ready" : "Unavailable",
        time(host.last_check),
        time(host.last_success),
        host.sudo_configured ? time(host.last_sudo_success) : "N/A",
        [host.ssh_reason, host.sudo_configured ? host.sudo_reason : ""].filter(Boolean).join(" · ") || "—"
      ];
      for (const value of values) row.insertCell().textContent = value;
      row.cells[1].className = host.status !== "active" ? "readiness-bad"
        : host.ssh_reason ? "readiness-warning" : "readiness-good";
      row.cells[2].className = !host.sudo_configured ? "readiness-neutral"
        : !host.sudo_ready ? "readiness-bad"
        : host.sudo_reason ? "readiness-warning" : "readiness-good";
    }
    $("readiness-hosts").replaceChildren(table);
  }
  const connection = $("connection");
  const wrap = $("connection-wrap");
  const details = $("connection-details");
  let pinned = false;
  function showReadiness(show) {
    details.hidden = !show;
    connection.setAttribute("aria-expanded", String(show));
  }
  wrap.addEventListener("mouseenter", () => showReadiness(true));
  wrap.addEventListener("mouseleave", () => { if (!pinned) showReadiness(false); });
  connection.addEventListener("click", () => {
    pinned = !pinned;
    showReadiness(pinned);
  });
  document.addEventListener("click", (event) => {
    if (!wrap.contains(event.target)) { pinned = false; showReadiness(false); }
  });
  wrap.addEventListener("keydown", (event) => {
    if (event.key === "Escape") { pinned = false; showReadiness(false); connection.focus(); }
  });
  function badge(text, kind) {
    return make("span", text, "chip " + kind);
  }
  const csrf = () => document.querySelector(
    'form[action="/console/logout"] input[name="csrf"]')?.value || "";
  function cancelFeedback(message) {
    const output = $("cancel-feedback");
    output.textContent = message;
    output.hidden = !message;
  }
  async function requestCancellation(job) {
    const id = job.id;
    if (state.cancelling.has(id) || !job.cancel_available) return;
    state.cancelling.add(id);
    cancelFeedback("");
    addOrUpdateRow(job);
    try {
      const response = await fetch("/console/api/jobs/" + escaped(id) + "/cancel", {
        method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ csrf: csrf() }),
      });
      if (response.status === 401) {
        location.assign("/console/login");
        return;
      }
      const result = await response.json().catch(() => ({}));
      if (!response.ok || !result.cancellation_requested)
        throw new Error(result.error || "Cancellation request failed (HTTP " + response.status + ")");
      // Keep Cancelling… locally until normal History polling reports a terminal state.
      if (state.selected === id) updateSelected().catch(() => {});
    } catch (error) {
      state.cancelling.delete(id);
      cancelFeedback("Cancellation not confirmed for " + id + ": " + error.message
        + ". Refresh the job before retrying.");
      const current = state.rows.get(id);
      if (current) addOrUpdateRow(current);
    }
  }
  function addOrUpdateRow(job, { prepend = false, bottom = false } = {}) {
    let row = rowBody.querySelector('tr[data-id="' + job.id + '"]');
    if (!row) {
      row = document.createElement("tr");
      row.dataset.id = job.id;
      row.addEventListener("click", () => selectJob(job.id).catch(() => setConnection(false)));
      if (prepend) rowBody.prepend(row);
      else if (bottom) rowBody.append(row);
      else rowBody.prepend(row);
    }
    if (tooltipTarget && row.contains(tooltipTarget)) hideCommandPreview();
    // Polling must not steal keyboard focus from the active cancel control.
    const hadCancelFocus = document.activeElement?.classList.contains("history-cancel")
      && row.contains(document.activeElement);
    if (!["queued", "running"].includes(job.status)) state.cancelling.delete(job.id);
    row.replaceChildren();
    const cells = [
      formatTableTime(job.created_at), tableStoryId(job.story_id), job.server,
      (job.command_preview || job.command || "—").split(/\r?\n/, 1)[0],
      modeName(job.mode), statusLabel(job.status), duration(job.elapsed_seconds)
    ];
    cells.forEach((value, index) => {
      const td = make("td", index < 4 || index === 6 ? value : undefined,
        index === 3 ? "mono" : index === 1 && job.story_id ? "story-id" : "");
      if (index === 1 && job.story_id) td.setAttribute("title", job.story_id);
      if (index === 3) {
        td.classList.add("command-cell");
        if (job.record_kind !== "file" && job.privileged === true) {
          const shield = rootShield();
          shield.setAttribute("role", "img");
          shield.removeAttribute("aria-hidden");
          shield.setAttribute("aria-label", "Root execution requested");
          td.prepend(shield);
        }
        td.tabIndex = 0;
        td.setAttribute("aria-label",
          (job.record_kind !== "file" && job.privileged === true
            ? "Root execution requested. " : "") +
          "Preview operation for record " + job.id);
        td.addEventListener("mouseenter", () => previewCommand(job.id, td));
        td.addEventListener("mouseleave", hideCommandPreview);
        td.addEventListener("focus", () => previewCommand(job.id, td));
        td.addEventListener("blur", hideCommandPreview);
        td.addEventListener("keydown", (event) => {
          if (event.key === "Enter") selectJob(job.id).catch(() => setConnection(false));
        });
      }
      if (index === 4) td.append(badge(value, job.mode || "async"));
      if (index === 5) {
        const pending = state.cancelling.has(job.id);
        const status = badge(pending ? "Cancelling…" : value, job.status || "queued");
        if (job.cancel_available && !pending) {
          const button = make("button", "×", "history-cancel");
          button.type = "button";
          button.title = "Request cancellation (stops the whole batch if this is a batch step)";
          button.setAttribute("aria-label", "Cancel job " + job.id);
          button.addEventListener("click", (event) => {
            event.preventDefault();
            event.stopPropagation();
            requestCancellation(job);
          });
          status.append(button);
        }
        td.append(status);
      }
      row.append(td);
    });
    row.classList.toggle("selected", state.selected === job.id);
    state.rows.set(job.id, job);
    if (hadCancelFocus) row.querySelector(".history-cancel")?.focus({ preventScroll: true });
  }
  function refreshRowTimes() {
    for (const row of rowBody.querySelectorAll("tr[data-id]")) {
      const job = state.rows.get(row.dataset.id);
      if (job) row.cells[0].textContent = formatTableTime(job.created_at);
    }
  }
  function updateTimeFormatButton() {
    const button = $("time-toggle");
    button.setAttribute("aria-pressed", String(state.relativeTime));
    const next = state.relativeTime ? "absolute" : "relative";
    button.setAttribute("aria-label", "Show " + next + " times");
    button.title = "Switch to " + next + " times";
  }
  function toggleTimeFormat() {
    state.relativeTime = !state.relativeTime;
    updateTimeFormatButton();
    refreshRowTimes();
    try { localStorage.setItem("ssh-mcp-console-time-format", state.relativeTime ? "relative" : "absolute"); }
    catch (_) {}
  }
  function updateMetricsNote() {
    const range = $("filters").elements.namedItem("time_range");
    const active = range.options[range.selectedIndex];
    $("metrics-note").textContent = (active ? active.textContent : "All time") +
      " · independent of other filters";
  }
  function refreshMetrics() {
    updateMetricsNote();
    const totals = state.totals;
    if (totals) {
      ["total", "running", "succeeded", "failed", "cancelled"].forEach((kind) => {
        $("metric-" + kind).textContent = Number(totals[kind] || 0).toLocaleString();
      });
    }
    $("empty").hidden = state.rows.size > 0;
    if (!state.rows.size) $("empty").textContent = "No jobs match the selected filters.";
  }
  function newJobsBanner() {
    const count = state.pending.size;
    $("new-jobs").hidden = count === 0;
    $("new-jobs").textContent = count + (count === 1 ? " new job" : " new jobs") + " - show";
  }
  function applyChange(job) {
    if (state.rows.has(job.id)) {
      if (matches(job)) addOrUpdateRow(job);
      else {
        // Persist the authoritative update even when it leaves this filter.
        // The polling expiry check then refreshes *any* page, not just page 1.
        state.rows.set(job.id, job);
        state.pending.delete(job.id);
        if (!["queued", "running"].includes(job.status)) state.cancelling.delete(job.id);
      }
    } else if (matches(job)) state.pending.set(job.id, job);
  }
  function showNewJobs() {
    state.pending.clear();
    newJobsBanner();
    goToPage(1, true);
  }
  function pageParams() {
    const params = new URLSearchParams(state.filters);
    params.set("limit", String(state.pageSize));
    params.set("page", String(state.page));
    return params.toString();
  }
  function pageButton(symbol, label, target, disabled, current = false) {
    const button = make("button", symbol);
    button.type = "button";
    button.setAttribute("aria-label", label);
    if (current) button.setAttribute("aria-current", "page");
    button.disabled = disabled;
    button.addEventListener("click", () => goToPage(target));
    return button;
  }
  function renderPagination() {
    const total = state.filteredTotal, page = state.page, pages = state.pageCount;
    const from = total ? (page - 1) * state.pageSize + 1 : 0;
    const to = Math.min(total, page * state.pageSize);
    $("page-summary").textContent = "Showing " + from + "–" + to + " of " + total;
    syncPageSizeControl();
    const nav = $("pagination");
    nav.replaceChildren();
    nav.append(
      pageButton("«", "First page", 1, page === 1),
      pageButton("‹", "Previous page", page - 1, page === 1),
    );
    const visible = new Set([1, pages]);
    if (pages <= 7) {
      for (let p = 1; p <= pages; p++) visible.add(p);
    } else if (page <= 3) {
      for (let p = 1; p <= 5; p++) visible.add(p);
    } else if (page >= pages - 2) {
      for (let p = pages - 4; p <= pages; p++) visible.add(p);
    } else {
      for (let p = page - 2; p <= page + 2; p++) visible.add(p);
    }
    let previous = 0;
    [...visible].sort((a, b) => a - b).forEach((p) => {
      if (previous && p > previous + 1) nav.append(make("span", "…", "ellipsis"));
      nav.append(pageButton(String(p), "Page " + p, p, p === page, p === page));
      previous = p;
    });
    nav.append(
      pageButton("›", "Next page", page + 1, page === pages),
      pageButton("»", "Last page", pages, page === pages),
    );
  }
  function fittedPageSize() {
    const header = $("history-table").tHead.getBoundingClientRect().height || 36;
    const row = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--history-row-height")) || 36;
    return Math.max(1, Math.min(100, Math.floor((listWrap.clientHeight - header - 1) / row)));
  }
  function syncPageSizeControl() {
    const select = $("rows-per-page");
    const max = fittedPageSize();
    select.options[0].textContent = String(max); // Automatic fit appears as "15", etc.
    for (const option of select.options) {
      if (option.value !== "auto") option.disabled = Number(option.value) > max;
    }
    if (state.preferredPageSize !== "auto" && Number(state.preferredPageSize) > max) {
      state.preferredPageSize = "auto";
    }
    select.value = state.preferredPageSize;
  }
  function resizePage() {
    syncPageSizeControl();
    const count = state.preferredPageSize === "auto"
      ? fittedPageSize() : Number(state.preferredPageSize);
    if (count === state.pageSize) return;
    state.pageSize = count;
    state.listGeneration++;
    loadJobs().catch(() => setConnection(false));
  }
  function goToPage(target, force = false) {
    const next = Math.max(1, Math.min(state.pageCount, target));
    if (next === state.page && !force) return;
    state.page = next;
    state.listGeneration++;
    hideCommandPreview();
    $("page-summary").textContent = "Loading page…";
    loadJobs().catch(() => {
      setConnection(false);
      $("page-summary").textContent = "Unable to load page";
    });
  }
  async function loadJobs() {
    const generation = state.listGeneration;
    const response = await api("/console/api/jobs?" + pageParams());
    // A slower reply for an old filter/page/size cannot overwrite newer results.
    if (generation !== state.listGeneration) return false;
    hideCommandPreview();
    const focusedCancel = document.activeElement?.classList.contains("history-cancel")
      ? document.activeElement.closest("tr[data-id]")?.dataset.id : null;
    rowBody.replaceChildren();
    state.rows.clear();
    state.pending.clear();
    state.changesCursor = response.changes_cursor;
    state.page = response.page;
    state.pageCount = response.page_count;
    state.filteredTotal = response.filtered_total;
    response.jobs.forEach((job) => addOrUpdateRow(job, { bottom: true }));
    if (focusedCancel) {
      const target = [...rowBody.querySelectorAll("tr[data-id]")].find(
        (row) => row.dataset.id === focusedCancel);
      target?.querySelector(".history-cancel")?.focus({ preventScroll: true });
    }
    state.totals = response.totals;
    state.summaryFetchedAt = Date.now();
    newJobsBanner();
    renderPagination();
    refreshMetrics();
    setConnection(true);
    return true;
  }
  function appendMeta(parent, label, value) {
    const wrap = make("div");
    wrap.append(make("div", label, "meta-label"), make("span", value, "meta-value"));
    parent.append(wrap);
  }
  function appendConversationMeta(parent, id) {
    if (!id) { appendMeta(parent, "Conversation ID", "—"); return; }
    const wrap = make("div");
    const value = make("button", id.length > 24 ? id.slice(0, 24) + "…" : id,
      "meta-value meta-conversation");
    value.type = "button";
    value.title = id; // Full ID is available on hover; never printed in details.
    value.setAttribute("aria-label", "Filter by this conversation");
    value.addEventListener("click", () => {
      const input = $("filters").elements.namedItem("conversation_id");
      input.value = id; // Filter by the exact, unshortened identity.
      updateConversationClear();
      clearTimeout(filterTimer);
      applyFilters();
      input.focus();
    });
    wrap.append(make("div", "Conversation ID", "meta-label"), value);
    parent.append(wrap);
  }
  function requestJsonData(job) {
    if (job.record_kind === "file") {
      // File body, patch text and transfers are deliberately not retained.
      return { note: "File request payload not retained", operation: job.operation_kind,
        path_summary: job.path_summary, byte_count: job.byte_count };
    }
    return job.request ?? { note: "Original request not recorded for this older job" };
  }
  function responseJsonData(job) {
    if (job.record_kind === "file") {
      return { status: job.status, error_code: job.error_code, error: job.error || null,
        byte_count: job.byte_count, file_metadata: job.file_metadata || {} };
    }
    // The original MCP response envelope is not retained. Represent the
    // recorded result and decoded captured streams, never invent its envelope.
    const complete = state.outputFullyLoaded &&
      !["queued", "running"].includes(job.status) &&
      Number.isSafeInteger(job.output_bytes) && state.outputCursor >= job.output_bytes;
    return { server: job.server, status: job.status, exit_code: job.exit_code,
      elapsed_seconds: job.elapsed_seconds, stdout: state.output.stdout,
      stderr: state.output.stderr, output_fully_loaded: complete,
      output_load_error: state.outputLoadError, error: job.error || null };
  }
  function renderResponseJson() {
    if (state.detail && state.responseJson)
      $("response-json").textContent = JSON.stringify(responseJsonData(state.detail), null, 2);
  }
  function renderJsonPanels() {
    $("request-readable").hidden = state.requestJson;
    $("request-json").hidden = !state.requestJson;
    $("response-readable").hidden = state.responseJson;
    $("response-json").hidden = !state.responseJson;
    for (const [part, enabled] of [["request", state.requestJson],
                                   ["response", state.responseJson]]) {
      const button = $(part + "-format-toggle");
      button.setAttribute("aria-pressed", String(enabled));
      button.setAttribute("aria-label", "Show " + part + (enabled ? " readable view" : " JSON"));
      button.title = "Switch to " + (enabled ? "readable view" : "JSON");
    }
    if (state.detail) {
      $("request-json").textContent = JSON.stringify(requestJsonData(state.detail), null, 2);
      renderResponseJson();
    }
  }
  function approvalLabel(code) {
    if (!code) return "—";
    const labels = { approved_config: "Approved · Config",
      approved_explicit: "Approved · Explicit", approved_timed: "Approved · Timed",
      denied_config: "Denied · Config", denied_explicit: "Denied · Explicit",
      denied_expired: "Denied · Expired", denied_disconnected: "Denied · Disconnected",
      denied_revoked: "Denied · Revoked" };
    return labels[code] || "—";
  }
  function renderDetail(job) {
    const refreshingSameJob = !$("detail").hidden && $("detail").dataset.jobId === job.id;
    $("detail-empty").hidden = true;
    $("detail").hidden = false;
    const isFile = job.record_kind === "file";
    const isBatch = job.record_kind === "batch";
    $("detail-title").textContent = isFile ? "File operation details"
      : isBatch ? "Batch request details" : "Job details";
    $("detail").dataset.jobId = job.id;
    for (const id of ["stdout-label", "stderr-label", "stdout", "stderr"]) {
      $(id).hidden = isFile || isBatch;
    }
    $("file-output-note").hidden = !(isFile || isBatch);
    $("file-output-note").textContent = isBatch
      ? (job.status === "denied"
        ? "Approval was denied before any batch step executed."
        : ["cwd_denied", "cwd_preflight"].includes(job.failure_kind)
          ? "Working-directory preflight failed; no batch command steps executed."
          : job.failure_kind === "pre_execution_rejected"
            ? "SSH request rejected before command execution; no batch command steps executed."
            : "No batch command steps executed; approval or scheduling failed.")
      : "File contents, patches and transfer payloads are never stored in history.";
    const meta = $("detail-meta");
    const restoreConversationFocus = refreshingSameJob
      && document.activeElement?.classList.contains("meta-conversation");
    meta.replaceChildren();
    [
      ["Status", statusLabel(job.status)], ["Approval", approvalLabel(job.approval_status)],
      ["Host", job.server],
      ["Story ID", job.story_id || "—"],
    ].forEach(([label, value]) => appendMeta(meta, label, value));
    appendConversationMeta(meta, job.conversation_id);
    const cancellation = job.cancellation_request;
    if (cancellation) {
      appendMeta(meta, "Cancellation requested via",
        cancellation.requested_via === "history" ? "Operator (History)" : "Agent (MCP)");
      appendMeta(meta, "Cancellation requested at", formatWhen(cancellation.requested_at));
      appendMeta(meta, "Cancellation reason", cancellation.reason);
    } else if (job.status === "cancelled") {
      appendMeta(meta, "Cancellation source", "Not recorded");
    }
    if (job.batch_step_outcome) {
      const step = job.batch_step_outcome;
      appendMeta(meta, "Parent batch outcome", statusLabel(step.batch_status));
      appendMeta(meta, "Batch step outcome", statusLabel(step.step_status));
      if (step.step_status === "unknown")
        appendMeta(meta, "Execution certainty",
          "Unknown — the remote command may have executed or caused side effects; inspect before retrying");
    }
    if (restoreConversationFocus)
      meta.querySelector(".meta-conversation")?.focus({ preventScroll: true });
    [
      ["Duration", duration(job.elapsed_seconds)],
      ["Mode", modeName(job.mode)], ["Exit code", job.exit_code]
    ].forEach(([label, value]) => appendMeta(meta, label, value));
    const request = job.request;
    if (isFile) {
      appendMeta(meta, "Method", job.operation_kind || "File operation");
    } else {
      if (isBatch && job.failure_kind)
        appendMeta(meta, "Failure kind", job.failure_kind);
      appendMeta(meta, "Run as", job.privileged === true
        ? (job.status === "denied" ? "root requested · not executed" : "root")
        : (job.run_as || "Not recorded"));
      if (job.privileged === true) {
        // root_started means the fixed privileged wrapper emitted its
        // startup marker, not that the requested command completed or even
        // started (e.g. root_setup_failed).
        appendMeta(meta, "Root wrapper startup",
          job.root_started === true ? "Confirmed" :
          job.root_started === false ? "Not started" : "Unconfirmed");
      }
      [
        ["Timeout", isBatch ? "Not executed" :
          request?.timeout_seconds != null ? request.timeout_seconds + " seconds" : "Not recorded"],
        [isBatch ? "Steps" : "Arguments", isBatch
          ? (request?.total_steps ?? "Not recorded")
          : (request?.argv?.length ?? "Not recorded")],
        ["Method", isBatch ? "execute_commands" :
          job.mode === "sync" ? "execute_command" : "submit_job"]
      ].forEach(([label, value]) => appendMeta(meta, label, value));
    }
    $("detail-reason-value").textContent = request?.reason || job.reason || "Not recorded";
    $("terminal-request").textContent = isFile ?
      (job.operation_kind + " " + job.path_summary) :
      (job.terminal_command || "Original request not recorded for this older job.");
    const props = $("request-properties");
    props.replaceChildren();
    props.hidden = !isFile;
    if (isFile) {
      [
        ["Operation", job.operation_kind], ["Path summary", job.path_summary],
        ["Bytes", job.byte_count], ["Error code", job.error_code || "—"]
      ].forEach(([label, value]) => appendMeta(props, label, value));
      const transfer = job.file_metadata?.transfer;
      if (transfer) {
        [["Direction", transfer.direction],
         ["Transfer mode", transfer.mode || "—"],
         ["Total file bytes", transfer.size ?? "—"],
         ["Chunk offset", transfer.offset ?? "—"],
         ["Next offset", transfer.next_offset ?? "—"],
         ["Last chunk", transfer.eof === undefined ? "—" : (transfer.eof ? "Yes" : "No")],
         ["File SHA-256", transfer.sha256 || "—"],
         ["Chunk SHA-256", transfer.chunk_sha256 || "—"]
        ].forEach(([label, value]) => appendMeta(props, label, value));
      }
      for (const result of (job.file_metadata?.outcomes || [])) {
        appendMeta(props, "File result", result.path + ": "
          + (result.action ? result.action + " — " : "")
          + result.status + (result.error_code ? " (" + result.error_code + ")" : "")
          + (result.moved_to ? " → " + result.moved_to : "")
          + (result.hash_error_code ? " (hash unavailable: " + result.hash_error_code + ")" : "")
          + (result.bytes ? " · " + result.bytes + " bytes" : ""));
      }
    }
    const error = $("job-error");
    error.hidden = !job.error;
    error.textContent = job.error || "";
    if (Number.isSafeInteger(job.output_bytes) && state.outputCursor < job.output_bytes)
      state.outputFullyLoaded = false;
    $("truncated").hidden = job.status !== "output_limit";
    $("technical-hash").textContent = isFile ? "Not applicable" : (job.command_sha256 || "Not recorded");
    const technical = $("technical-metadata");
    technical.replaceChildren();
    [[isFile ? "Operation ID" : "Job ID", job.id],
     ["Actor", job.actor], ["Submitted", formatWhen(job.created_at)],
     ["Started", formatWhen(job.started_at)],
     ["Finished", formatWhen(job.ended_at)]].forEach(
      ([label, value]) => appendMeta(technical, label, value));
    renderJsonPanels();
  }
  function resetOutput() {
    state.outputGeneration++;
    state.outputCursor = 0;
    state.output = { stdout: "", stderr: "" };
    state.outputFullyLoaded = false;
    state.outputLoadError = null;
    state.decoders = { stdout: new TextDecoder("utf-8"), stderr: new TextDecoder("utf-8") };
    $("stdout").textContent = "";
    $("stderr").textContent = "";
  }
  function writeOutput(stream) {
    const element = $(stream);
    const atBottom = element.scrollTop + element.clientHeight >= element.scrollHeight - 25;
    const previousScroll = element.scrollTop;
    element.textContent = state.output[stream] || "(empty)";
    element.scrollTop = atBottom ? element.scrollHeight : previousScroll;
    renderResponseJson();
  }
  async function readOutput(jobId) {
    const generation = state.outputGeneration;
    if (state.loadingOutputGeneration === generation) return;
    state.loadingOutputGeneration = generation;
    state.outputFullyLoaded = false;
    state.outputLoadError = null;
    let staleEndRetries = 0;
    try {
      // The default 256 KiB capture needs up to 16 pages at 16 KiB/page.
      // Bound each fetch pass, and never label any remaining pages as complete.
      for (let index = 0; index < 32; index++) {
        if (state.selected !== jobId || state.outputGeneration !== generation) return;
        const page = await api("/console/api/jobs/" + escaped(jobId) +
                               "/output?cursor=" + state.outputCursor + "&max_bytes=16384");
        if (state.selected !== jobId || state.outputGeneration !== generation) return;
        const previousCursor = state.outputCursor;
        for (const item of page.chunks) {
          if (!["stdout", "stderr"].includes(item.stream)) continue;
          const raw = atob(item.data_base64);
          const bytes = Uint8Array.from(raw, (char) => char.charCodeAt(0));
          state.output[item.stream] += state.decoders[item.stream].decode(bytes, { stream: true });
        }
        if (page.next_cursor < previousCursor)
          throw new Error("Output cursor moved backwards");
        state.outputCursor = page.next_cursor;
        // A response can represent an earlier WAL snapshot than a terminal
        // detail refresh received while this fetch was in flight.
        const latest = state.detail;
        const recordedBytes = latest?.output_bytes;
        const behindLatest = Number.isSafeInteger(recordedBytes)
          && state.outputCursor < recordedBytes;
        state.outputFullyLoaded = !page.truncated && !behindLatest
          && Number.isSafeInteger(recordedBytes)
          && !["queued", "running"].includes(latest.status);
        if (!page.truncated && behindLatest) {
          if (++staleEndRetries > 1)
            throw new Error("Output ended before the latest recorded byte count");
          continue; // Re-read the remaining bytes from the final snapshot.
        }
        if (!page.truncated) break;
        if (page.next_cursor === previousCursor)
          throw new Error("Output pagination did not advance");
      }
    } catch (error) {
      if (state.selected === jobId && state.outputGeneration === generation)
        state.outputLoadError = "Unable to load all captured output";
      throw error;
    } finally {
      if (state.selected === jobId && state.outputGeneration === generation) {
        writeOutput("stdout"); writeOutput("stderr");
      }
      if (state.loadingOutputGeneration === generation) state.loadingOutputGeneration = null;
    }
  }
  async function selectJob(id) {
    state.selected = id;
    state.detail = null;
    for (const row of rowBody.querySelectorAll("tr[data-id]"))
      row.classList.toggle("selected", row.dataset.id === id);
    resetOutput();
    const generation = state.outputGeneration;
    $("detail").hidden = true;
    delete $("detail").dataset.jobId;
    $("detail-empty").hidden = false;
    $("detail-empty").textContent = "Loading job details…";
    $("request-json").textContent = "";
    $("response-json").textContent = "";
    let response;
    try {
      response = await api("/console/api/jobs/" + escaped(id));
    } catch (error) {
      if (state.selected === id && state.outputGeneration === generation)
        $("detail-empty").textContent = "Unable to load job details. Select the job again to retry.";
      throw error;
    }
    if (state.selected !== id || state.outputGeneration !== generation) return;
    state.detail = response.job;
    renderDetail(response.job);
    if (!["file", "batch"].includes(response.job.record_kind)) await readOutput(id);
    else { writeOutput("stdout"); writeOutput("stderr"); }
  }
  async function updateSelected() {
    if (!state.selected) return;
    const response = await api("/console/api/jobs/" + escaped(state.selected));
    if (state.selected !== response.job.id) return;
    state.detail = response.job;
    renderDetail(response.job);
    if (!["file", "batch"].includes(response.job.record_kind)) await readOutput(state.selected);
  }
  async function poll() {
    if (state.busy) return;
    if (document.hidden) { setTimeout(poll, 5000); return; }
    state.busy = true;
    try {
      let refreshSelected = false;
      let sawChanges = false;
      if (state.changesCursor) {
        for (let i = 0; i < 8; i++) {
          const data = await api("/console/api/changes?after=" + escaped(state.changesCursor));
          // Reuse the visible History poll; approval alerts have a separate
          // low-volume SSE channel so hidden tabs never fetch job details.
          if (Array.isArray(data.pending_approvals) && Array.isArray(data.active_grants)) {
            document.dispatchEvent(new CustomEvent("ssh-mcp-approvals-snapshot", { detail: data }));
          }
          if (data.readiness) state.readiness = data.readiness;
          state.changesCursor = data.changes_cursor;
          if (data.jobs.length) sawChanges = true;
          data.jobs.forEach((job) => {
            if (job.id === state.selected) refreshSelected = true;
            applyChange(job);
          });
          if (!data.has_more) break;
        }
      }
      // A completed child has no further job events, but its parent batch
      // may still run, be cancelled, or finish. Refresh until the parent
      // reaches a terminal status so Details never leave a stale outcome.
      const activeParent = state.detail?.batch_step_outcome
        && ["queued", "running"].includes(state.detail.batch_step_outcome.batch_status);
      if (refreshSelected || activeParent
          || (state.detail && ["queued", "running"].includes(state.detail.status)))
        await updateSelected();
      if (sawChanges || Date.now() - state.summaryFetchedAt > 10000) {
        const generation = state.listGeneration;
        const timeRange = state.filters.time_range || "";
        const summary = await api("/console/api/summary?time_range=" + escaped(timeRange));
        // A slower summary for the old range must not replace newer KPI values.
        if (generation === state.listGeneration) {
          state.totals = summary.totals;
          state.summaryFetchedAt = Date.now();
        }
      }
      // Refresh the active first page when new jobs arrive, without
      // exceeding the visible row budget. Other pages retain a notice.
      const expired = [...state.rows.values()].some((job) => !matches(job));
      if (expired || (sawChanges && state.page === 1)) await loadJobs();
      newJobsBanner();
      refreshMetrics();
      if (state.relativeTime) refreshRowTimes();
      setConnection(true);
    } catch (error) {
      setConnection(false);
    } finally {
      state.busy = false;
      setTimeout(poll, document.hidden ? 5000 : 1000);
    }
  }
  function restorePreferences() {
    try {
      state.relativeTime = localStorage.getItem("ssh-mcp-console-time-format") === "relative";
      const rows = localStorage.getItem("ssh-mcp-console-rows");
      if (["10", "15", "20", "25", "50"].includes(rows)) state.preferredPageSize = rows;
      const width = Number(localStorage.getItem("ssh-mcp-console-split"));
      if (width >= 28 && width <= 72) document.documentElement.style.setProperty("--left-width", width + "%");
      const filters = JSON.parse(localStorage.getItem("ssh-mcp-console-filters") || "{}");
      if (filters && typeof filters === "object") {
        state.privilegedOnly = filters.privileged === "true";
        Object.entries(filters).forEach(([name, value]) => {
          const input = $("filters").elements.namedItem(name);
          if (input && typeof value === "string") input.value = value;
        });
      }
      const jobInfo = localStorage.getItem("ssh-mcp-console-job-info-open");
      const technical = localStorage.getItem("ssh-mcp-console-technical-open");
      $("job-info-panel").open = jobInfo === null ? true : jobInfo === "true";
      $("technical-details").open = technical === "true";
    } catch (_) {}
    state.filters = currentFilters();
    updatePrivilegedButton();
    updateTimeFormatButton();
    updateMetricsNote();
  }
  async function loadRegisteredHosts() {
    const response = await api("/console/api/hosts");
    if (response.readiness) state.readiness = response.readiness;
    setConnection(true);
    const select = $("filters").elements.namedItem("host");
    select.replaceChildren(new Option("All hosts", ""));
    for (const host of response.hosts) {
      if (typeof host === "string") select.add(new Option(host, host));
    }
  }
  function updateCommandClear() {
    $("clear-command").hidden = !$("filters").elements.namedItem("command").value;
  }
  function updatePrivilegedButton() {
    const button = $("privileged-filter");
    button.setAttribute("aria-pressed", String(state.privilegedOnly));
    button.classList.toggle("is-active", state.privilegedOnly);
    button.title = state.privilegedOnly ? "Show all commands" : "Show root commands only";
  }
  function updateConversationClear() {
    $("clear-conversation").hidden =
      !$("filters").elements.namedItem("conversation_id").value;
  }
  function enableSplitter() {
    const splitter = $("splitter"), workspace = $("workspace");
    let dragging = false;
    splitter.addEventListener("pointerdown", (event) => {
      dragging = true;
      splitter.setPointerCapture(event.pointerId);
      event.preventDefault();
    });
    splitter.addEventListener("pointermove", (event) => {
      if (!dragging) return;
      const bounds = workspace.getBoundingClientRect();
      const raw = ((event.clientX - bounds.left) / bounds.width) * 100;
      const percent = Math.min(72, Math.max(28, raw));
      document.documentElement.style.setProperty("--left-width", percent + "%");
    });
    splitter.addEventListener("pointerup", () => {
      dragging = false;
      const width = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--left-width"));
      if (Number.isFinite(width)) try { localStorage.setItem("ssh-mcp-console-split", String(width)); } catch (_) {}
    });
    splitter.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
      event.preventDefault();
      const previous = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--left-width")) || 49;
      const width = Math.min(72, Math.max(28, previous + (event.key === "ArrowRight" ? 2 : -2)));
      document.documentElement.style.setProperty("--left-width", width + "%");
      try { localStorage.setItem("ssh-mcp-console-split", String(width)); } catch (_) {}
    });
  }
  $("time-toggle").addEventListener("click", toggleTimeFormat);
  $("privileged-filter").addEventListener("click", () => {
    state.privilegedOnly = !state.privilegedOnly;
    updatePrivilegedButton();
    applyFilters();
  });
  let filterTimer = null;
  function applyFilters() {
    const next = currentFilters();
    if (JSON.stringify(next) === JSON.stringify(state.filters)) return;
    const timeRangeChanged = next.time_range !== state.filters.time_range;
    state.filters = next;
    updateMetricsNote();
    if (timeRangeChanged) {
      // Do not show totals from the previously selected time window while loading.
      state.totals = null;
      for (const kind of ["total", "running", "succeeded", "failed", "cancelled"]) {
        $("metric-" + kind).textContent = "—";
      }
    }
    state.page = 1;
    state.listGeneration++;
    remember();
    hideCommandPreview();
    $("empty").hidden = false;
    $("empty").textContent = "Loading history...";
    loadJobs().catch(() => {
      setConnection(false);
      $("empty").hidden = false;
      $("empty").textContent = "Unable to load history. Change a filter to retry.";
    });
  }
  $("filters").addEventListener("input", (event) => {
    if (event.target.tagName !== "INPUT") return;
    if (event.target.name === "command") updateCommandClear();
    if (event.target.name === "conversation_id") updateConversationClear();
    clearTimeout(filterTimer);
    filterTimer = setTimeout(applyFilters, 250); // Debounce text entry only.
  });
  $("filters").addEventListener("change", () => {
    clearTimeout(filterTimer);
    applyFilters(); // Selects and committed text edits apply immediately.
  });
  $("filters").addEventListener("submit", (event) => {
    event.preventDefault();
    clearTimeout(filterTimer);
    applyFilters(); // Enter works without an Apply button.
  });
  listWrap.addEventListener("scroll", hideCommandPreview, { passive: true });
  window.addEventListener("resize", hideCommandPreview);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") hideCommandPreview();
  });
  $("rows-per-page").addEventListener("change", (event) => {
    state.preferredPageSize = event.target.value;
    try { localStorage.setItem("ssh-mcp-console-rows", state.preferredPageSize); } catch (_) {}
    state.page = 1;
    state.pageSize = state.preferredPageSize === "auto"
      ? fittedPageSize() : Math.min(fittedPageSize(), Number(state.preferredPageSize));
    state.listGeneration++;
    syncPageSizeControl();
    loadJobs().catch(() => setConnection(false));
  });
  $("clear-command").addEventListener("click", () => {
    const input = $("filters").elements.namedItem("command");
    input.value = "";
    updateCommandClear();
    clearTimeout(filterTimer);
    applyFilters();
    input.focus();
  });
  $("clear-conversation").addEventListener("click", () => {
    const input = $("filters").elements.namedItem("conversation_id");
    input.value = "";
    updateConversationClear();
    clearTimeout(filterTimer);
    applyFilters();
    input.focus();
  });
  $("new-jobs").addEventListener("click", showNewJobs);
  $("request-format-toggle").addEventListener("click", () => {
    state.requestJson = !state.requestJson;
    renderJsonPanels();
  });
  $("response-format-toggle").addEventListener("click", () => {
    state.responseJson = !state.responseJson;
    renderJsonPanels();
  });
  enableSplitter();
  // Host aliases come from the already validated server inventory, not
  // user-supplied history, addresses, tokens or an unauthenticated endpoint.
  loadRegisteredHosts().catch(() => setConnection(false)).finally(() => {
    restorePreferences();
    // Register after restoring: initial <details open> events must not
    // overwrite previously saved collapsed states on page load.
    for (const [id, key] of [
      ["job-info-panel", "ssh-mcp-console-job-info-open"],
      ["technical-details", "ssh-mcp-console-technical-open"]
    ]) {
      $(id).addEventListener("toggle", () => {
        try { localStorage.setItem(key, String($(id).open)); } catch (_) {}
      });
    }
    updateCommandClear();
    updateConversationClear();
    syncPageSizeControl();
    state.pageSize = state.preferredPageSize === "auto"
      ? fittedPageSize() : Number(state.preferredPageSize);
    let resizeFrame = null;
    const onResize = () => {
      hideCommandPreview();
      if (resizeFrame !== null) return;
      resizeFrame = requestAnimationFrame(() => {
        resizeFrame = null;
        resizePage();
      });
    };
    new ResizeObserver(onResize).observe(listWrap);
    window.addEventListener("resize", onResize);
    loadJobs().then(() => {
      if (state.rows.size) selectJob(state.rows.keys().next().value).catch(() => setConnection(false));
    }).catch(() => setConnection(false)).finally(() => setTimeout(poll, 1000));
  });
})();
