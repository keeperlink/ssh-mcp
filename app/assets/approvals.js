"use strict";
/* Browser-only approvals; no SSH OAuth token or command-execution access. */
(() => {
  const $ = (id) => document.getElementById(id);
  const layer = $("approval-layer");
  if (!layer) return;
  const state = {
    pending: new Map(), grants: new Map(), seen: new Map(), notices: new Map(),
    notified: new Set(), localPending: new Map(),
    conversationNumbers: new Map(), nextConversation: 1,
    active: null, busy: false, instance: null, revision: -1,
    muted: false, notificationsEnabled: false
  };
  let previousFocus = null;
  let audio = null;
  const remaining = (expiry) => Math.max(0, Math.ceil(Number(expiry) - Date.now() / 1000));
  const countdown = (seconds) => {
    if (seconds < 60) return seconds + "s";
    const minutes = Math.ceil(seconds / 60);
    if (minutes <= 99) return minutes + "m";
    // Keep long-lived bubbles compact and stable: after 99 minutes show hours only.
    return Math.round(minutes / 60) + "h";
  };
  const conversationNumber = (id) => {
    if (typeof id !== "string" || !id) return null;
    if (!state.conversationNumbers.has(id)) {
      // Opaque conversation scope IDs distinguish OAuth sessions, not hosts.
      // Local indices never authorize a request or expose session IDs.
      if (state.conversationNumbers.size >= 1024) {
        // Preserve labels already shown on live grants and pending requests.
        const live = new Set([...state.pending.values(), ...state.grants.values()]
          .map((entry) => entry.conversation_scope_id));
        for (const candidate of state.conversationNumbers.keys()) {
          if (!live.has(candidate)) {
            state.conversationNumbers.delete(candidate);
            break;
          }
        }
      }
      state.conversationNumbers.set(id, state.nextConversation++);
    }
    return state.conversationNumbers.get(id);
  };
  const csrf = () => document.querySelector('form[action="/console/logout"] input[name="csrf"]')?.value || "";

  function closeNotice(id) {
    const notice = state.notices.get(id);
    if (notice) {
      try { notice.close(); } catch (_) {}
      state.notices.delete(id);
    }
  }
  function alertSound() {
    if (state.muted) return;
    try {
      const Audio = window.AudioContext || window.webkitAudioContext;
      if (!Audio) return;
      audio ||= new Audio();
      if (audio.state === "suspended") audio.resume().catch(() => {});
      const oscillator = audio.createOscillator();
      const gain = audio.createGain();
      oscillator.type = "sine";
      oscillator.frequency.value = 660;
      gain.gain.setValueAtTime(0.0001, audio.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.085, audio.currentTime + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, audio.currentTime + 0.25);
      oscillator.connect(gain).connect(audio.destination);
      oscillator.start();
      oscillator.stop(audio.currentTime + 0.26);
    } catch (_) {
      // Browser autoplay policy may forbid sound until an operator gesture.
    }
  }
  function desktopNotice(request) {
    if (!state.notificationsEnabled || !("Notification" in window)
        || Notification.permission !== "granted"
        || state.notified.has(request.id) || remaining(request.expires_at) === 0) return;
    state.notified.add(request.id);
    if (state.notified.size > 1024) state.notified.delete(state.notified.values().next().value);
    try {
      const notice = new Notification(
        request.requires_root ? "Root approval required" : "Host access approval: " + request.host, {
        body: "Waiting for approval · " + remaining(request.expires_at) + "s remaining",
        tag: "ssh-mcp-host-approval-" + request.id,
      });
      notice.onclick = () => {
        window.focus();
        showActive(request.id);
        $("approval-grant").focus();
      };
      notice.onclose = () => state.notices.delete(request.id);
      state.notices.set(request.id, notice);
    } catch (_) {
      // Desktop notifications may be unavailable despite granted permission.
    }
  }
  function renderPreview(request) {
    const container = $("approval-steps");
    const fallback = $("approval-summary");
    const heading = $("approval-summary-title");
    const sequence = $("approval-sequence");
    container.replaceChildren();
    const steps = Array.isArray(request.steps) ? request.steps : [];
    if (!steps.length || !steps.every((step) => step && typeof step.command === "string")) {
      container.hidden = true;
      fallback.hidden = false;
      fallback.textContent = request.summary || "No preview available";
      heading.textContent = "Requested command / paths";
      sequence.hidden = true;
      return;
    }
    fallback.hidden = true;
    heading.textContent = "Requested commands (" + steps.length + " steps)";
    sequence.hidden = false;
    steps.forEach((step, index) => {
      const details = document.createElement("details");
      details.className = "approval-step";
      // Preserve the established compact batch layout. Every complete step
      // remains available to expand without truncating the request.
      details.open = index === 0;
      const summary = document.createElement("summary");
      const title = document.createElement("span");
      title.className = "approval-step-title";
      const name = String(step.title || "").trim();
      title.textContent = "Step " + (index + 1) +
        (name && name !== "Step " + (index + 1) ? " — " + name : "");
      summary.append(title);
      if (step.interpreter) {
        const interpreter = document.createElement("span");
        interpreter.className = "approval-step-interpreter";
        interpreter.textContent = String(step.interpreter);
        summary.append(interpreter);
      }
      const command = document.createElement("pre");
      command.textContent = step.command; // Never interpret operator command as HTML.
      details.append(summary, command);
      if (typeof step.options === "string") {
        const options = document.createElement("pre");
        options.className = "approval-step-options";
        options.textContent = step.options;
        details.append(options);
      }
      if (step.truncated) {
        const warning = document.createElement("div");
        warning.className = "approval-truncated";
        warning.textContent = "Command preview truncated — review full request before granting";
        details.append(warning);
      }
      container.append(details);
    });
    container.hidden = false;
  }
  function showActive(preferred) {
    const previousId = state.active;
    if (preferred && state.pending.has(preferred)) state.active = preferred;
    else if (!state.active || !state.pending.has(state.active))
      state.active = state.pending.keys().next().value || null;
    const request = state.pending.get(state.active);
    if (!request) {
      layer.hidden = true;
      if (previousId && previousFocus?.isConnected) previousFocus.focus();
      previousFocus = null;
      state.active = null;
      return;
    }
    if (previousId !== state.active || layer.hidden) {
      if (layer.hidden) previousFocus = document.activeElement;
      $("approval-host").textContent = request.host || "Unknown";
      const number = conversationNumber(request.conversation_scope_id);
      $("approval-conversation").textContent = number ? "Conversation #" + number : "Not provided";
      $("approval-client").textContent = request.client_id || "MCP client";
      const timedAllowed = Boolean(request.conversation_id) && request.timed_grants_allowed !== false;
      $("approval-duration-warning").hidden = timedAllowed;
      $("approval-tool").textContent = request.tool || "Operation";
      $("approval-reason").textContent = request.reason || "Not specified";
      const root = request.requires_root === true;
      layer.classList.toggle("is-root", root);
      $("approval-title").textContent = root
        ? "Run as root — operator approval" : "Restricted host access";
      $("approval-explainer").textContent = root
        ? (request.requires_host
          ? "Approve SSH host access and root execution for this exact request."
          : "Approve execution as root for this exact request.")
          + (timedAllowed ? " A timed grant also authorizes subsequent root requests in this conversation and host." : "")
        : "An agent is waiting for your approval. Access will not be granted automatically.";
      renderPreview(request);
      layer.querySelector('input[name="approval-duration"][value="once"]').checked = true;
      $("approval-feedback").hidden = true;
      layer.hidden = false;
      $("approval-grant").focus();
    }
    updateClock();
  }
  function grantName(grant) {
    const number = conversationNumber(grant.conversation_scope_id);
    return grant.host + (number ? " [" + number + "]" : "");
  }
  function revokeButton(grant, name) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "×";
    button.title = grant.kind === "root" ? "Revoke root grant" : "Revoke host grant";
    button.setAttribute("aria-label", "Revoke "
      + (grant.kind === "root" ? "root" : "host access") + " for " + name);
    button.addEventListener("click", () => submit(
      "/console/api/grants/" + encodeURIComponent(grant.id) + "/revoke",
      {}, grant.id, true
    ));
    return button;
  }
  function rootShield() {
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
  }
  function rootSection(grant, name) {
    // Shared compact root renderer: nested in green SSH access or alone.
    const section = document.createElement("span");
    section.className = "grant-root-detail";
    section.dataset.id = grant.id;
    const timer = document.createElement("span");
    timer.className = "grant-countdown";
    section.append(rootShield(), timer, revokeButton(grant, name));
    return section;
  }
  function renderGrants() {
    const container = $("grant-chips");
    const current = [...state.grants.values()].filter(
      (grant) => remaining(grant.expires_at) > 0
    );
    // An opaque, session-scoped pairing ID avoids combining unrelated
    // OAuth sessions that happen to use the same host and conversation.
    const roots = new Map(current.filter(
      (grant) => grant.kind === "root" && typeof grant.scope_id === "string"
    ).map((grant) => [grant.scope_id, grant]));
    const paired = new Set();
    const active = new Set();
    for (const host of current.filter((grant) => grant.kind !== "root")) {
      const root = roots.get(host.scope_id);
      if (root) paired.add(root.id);
      active.add(host.id);
      let chip = [...container.children].find((node) => node.dataset.id === host.id);
      if (!chip) {
        chip = document.createElement("span");
        chip.className = "grant-chip";
        chip.dataset.id = host.id;
        const name = document.createElement("span");
        name.className = "grant-name";
        name.textContent = grantName(host);
        const timer = document.createElement("span");
        timer.className = "grant-countdown";
        timer.textContent = countdown(remaining(host.expires_at));
        chip.append(name, timer, revokeButton(host, name.textContent));
        container.append(chip);
      }
      const timer = chip.querySelector(":scope > .grant-countdown");
      timer.hidden = Boolean(root) &&
        Math.abs(Number(host.expires_at) - Number(root.expires_at)) < 1;
      timer.textContent = countdown(remaining(host.expires_at));
      let section = chip.querySelector(".grant-root-detail");
      if (root) {
        if (!section || section.dataset.id !== root.id) {
          section?.remove();
          section = rootSection(root, grantName(host));
          chip.insertBefore(section, chip.lastElementChild);
        }
        section.querySelector(".grant-countdown").textContent =
          countdown(remaining(root.expires_at));
      } else {
        section?.remove();
      }
    }
    for (const root of current.filter((grant) => grant.kind === "root")) {
      if (paired.has(root.id)) continue;
      active.add(root.id);
      let chip = [...container.children].find((node) => node.dataset.id === root.id);
      if (!chip) {
        chip = document.createElement("span");
        chip.className = "grant-chip grant-root";
        chip.dataset.id = root.id;
        const name = document.createElement("span");
        name.className = "grant-name";
        name.textContent = grantName(root);
        chip.append(name, rootSection(root, name.textContent));
        container.append(chip);
      }
      chip.querySelector(".grant-countdown").textContent =
        countdown(remaining(root.expires_at));
    }
    for (const chip of [...container.children]) {
      if (!active.has(chip.dataset.id)) chip.remove();
    }
  }
  function updateClock() {
    const request = state.pending.get(state.active);
    if (!request) return;
    const seconds = remaining(request.expires_at);
    $("approval-expiry").textContent = seconds + "s";
    $("approval-grant").disabled = state.busy || seconds === 0;
    $("approval-deny").disabled = state.busy;
    $("approval-close").disabled = state.busy;
    const timedAllowed = Boolean(request.conversation_id) && request.timed_grants_allowed !== false;
    for (const control of layer.querySelectorAll('input[name="approval-duration"]'))
      control.disabled = state.busy || seconds === 0 || (!timedAllowed && control.value !== "once");
  }
  function tick() {
    for (const [id, request] of state.pending) {
      if (remaining(request.expires_at) === 0) {
        state.pending.delete(id);
        closeNotice(id);
      }
    }
    for (const [id, grant] of state.grants) {
      if (remaining(grant.expires_at) === 0) state.grants.delete(id);
    }
    showActive();
    renderGrants();
  }
  function applySnapshot(data) {
    if (!Array.isArray(data.pending_approvals) || !Array.isArray(data.active_grants)) return;
    if (typeof data.approval_instance === "string" && Number.isInteger(data.approval_revision)) {
      if (state.instance === data.approval_instance && data.approval_revision < state.revision)
        return;
      if (state.instance !== data.approval_instance) {
        state.instance = data.approval_instance;
        state.revision = -1;
        state.seen.clear();
        state.localPending.clear();
      }
      state.revision = data.approval_revision;
      for (const [id, revision] of state.localPending) {
        if (state.revision > revision) state.localPending.delete(id);
      }
    }
    const next = new Map();
    for (const request of data.pending_approvals) {
      if (!request || typeof request.id !== "string" || !Number.isFinite(request.expires_at)
          || remaining(request.expires_at) === 0) continue;
      if (state.localPending.has(request.id)) {
        if (state.revision <= state.localPending.get(request.id)) continue;
        state.localPending.delete(request.id);
      }
      next.set(request.id, request);
      if (!state.seen.has(request.id)) {
        state.seen.set(request.id, Date.now());
        if (state.seen.size > 1024) state.seen.delete(state.seen.keys().next().value);
        alertSound();
      }
      desktopNotice(request);
    }
    for (const id of state.pending.keys()) {
      if (!next.has(id)) closeNotice(id);
    }
    state.pending = next;
    state.grants = new Map(data.active_grants.filter(
      (grant) => grant && typeof grant.id === "string" && Number.isFinite(grant.expires_at)
    ).map((grant) => [grant.id, grant]));
    tick();
  }

  async function submit(path, fields, id, revoke = false) {
    if (state.busy) return;
    if (!revoke && (!state.pending.has(id) || remaining(state.pending.get(id).expires_at) === 0))
      return;
    state.busy = true;
    updateClock();
    try {
      const response = await fetch(path, {
        method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ ...fields, csrf: csrf() }),
      });
      if (response.status === 401) {
        location.assign("/console/login");
        return;
      }
      if (revoke) {
        if (!response.ok && response.status !== 404)
          throw new Error("Operation failed (HTTP " + response.status + ")");
        // The server version is authoritative. Ignore this POST when a
        // newer snapshot already arrived via SSE or the visible poll.
        // In particular, never hide a newly granted root permission.
        const snapshot = await response.json();
        if (typeof snapshot.approval_instance !== "string"
            || !Number.isInteger(snapshot.approval_revision)
            || !Array.isArray(snapshot.active_grants)
            || !Array.isArray(snapshot.pending_approvals))
          throw new Error("Grant state unavailable; refresh required");
        applySnapshot(snapshot);
      } else if (!response.ok) {
        if (response.status === 404) {
          state.pending.delete(id);
          closeNotice(id);
        } else {
          throw new Error("Operation failed (HTTP " + response.status + ")");
        }
      } else {
        state.pending.delete(id);
        state.localPending.set(id, state.revision);
        closeNotice(id);
      }
      showActive();
      renderGrants();
    } catch (error) {
      const feedback = $(revoke ? "approval-status" : "approval-feedback");
      feedback.textContent = error.message || "Could not contact server";
      feedback.hidden = false;
    } finally {
      state.busy = false;
      tick();
    }
  }

  function updateMuteButton() {
    const button = $("approval-mute");
    button.classList.toggle("is-off", state.muted);
    button.setAttribute("aria-pressed", String(!state.muted));
    button.setAttribute("aria-label", state.muted ? "Unmute sound" : "Mute sound");
    button.title = state.muted ? "Sound off" : "Sound on";
  }
  try { state.muted = localStorage.getItem("ssh-mcp-console-approval-muted") === "true"; }
  catch (_) {}
  updateMuteButton();
  $("approval-mute").addEventListener("click", () => {
    state.muted = !state.muted;
    try { localStorage.setItem("ssh-mcp-console-approval-muted", String(state.muted)); }
    catch (_) {}
    updateMuteButton();
    if (!state.muted) {
      // Unlock audio only from an explicit user gesture.
      try {
        const Audio = window.AudioContext || window.webkitAudioContext;
        if (Audio) { audio ||= new Audio(); audio.resume().catch(() => {}); }
      } catch (_) {}
    }
  });
  const notificationButton = $("approval-notifications");
  try {
    const saved = localStorage.getItem("ssh-mcp-console-approval-notifications");
    state.notificationsEnabled = saved === "true" ||
      (saved === null && "Notification" in window && Notification.permission === "granted");
  } catch (_) {
    state.notificationsEnabled = "Notification" in window && Notification.permission === "granted";
  }
  function updateNotificationButton() {
    if (!("Notification" in window)) {
      notificationButton.hidden = true;
      return;
    }
    const blocked = Notification.permission === "denied";
    const enabled = !blocked && Notification.permission === "granted" &&
      state.notificationsEnabled;
    notificationButton.disabled = blocked;
    notificationButton.classList.toggle("is-off", !enabled);
    notificationButton.setAttribute("aria-pressed", String(enabled));
    notificationButton.setAttribute("aria-label", blocked ? "Desktop notifications blocked" :
      enabled ? "Disable desktop notifications" : "Enable desktop notifications");
    notificationButton.title = blocked ? "Desktop notifications blocked by browser" :
      enabled ? "Desktop notifications on" : "Desktop notifications off";
  }
  updateNotificationButton();
  notificationButton.addEventListener("click", async () => {
    if (!("Notification" in window) || Notification.permission === "denied") return;
    if (Notification.permission === "default") {
      const permission = await Notification.requestPermission();
      state.notificationsEnabled = permission === "granted";
    } else {
      state.notificationsEnabled = !state.notificationsEnabled;
    }
    try {
      localStorage.setItem("ssh-mcp-console-approval-notifications",
        String(state.notificationsEnabled));
    } catch (_) {}
    updateNotificationButton();
    if (state.notificationsEnabled) {
      for (const request of state.pending.values()) desktopNotice(request);
    } else {
      for (const id of state.notices.keys()) closeNotice(id);
    }
  });
  $("approval-grant").addEventListener("click", () => {
    if (state.active) submit(
      "/console/api/approvals/" + encodeURIComponent(state.active) + "/grant",
      { duration: layer.querySelector('input[name="approval-duration"]:checked')?.value || "once" },
      state.active
    );
  });
  function denyActive() {
    if (state.active) submit(
      "/console/api/approvals/" + encodeURIComponent(state.active) + "/deny",
      {}, state.active
    );
  }
  $("approval-deny").addEventListener("click", denyActive);
  $("approval-close").addEventListener("click", denyActive);
  layer.addEventListener("keydown", (event) => {
    if (event.key === "Escape") event.preventDefault(); // Never grant/dismiss by Escape.
    if (event.key !== "Tab") return;
    const controls = [...layer.querySelectorAll("button, input, summary")]
      .filter((control) => !control.disabled && control.getClientRects().length);
    const first = controls[0], last = controls.at(-1);
    if (event.shiftKey && document.activeElement === first) {
      last.focus(); event.preventDefault();
    } else if (!event.shiftKey && document.activeElement === last) {
      first.focus(); event.preventDefault();
    }
  });
  document.addEventListener("ssh-mcp-approvals-snapshot", (event) => applySnapshot(event.detail));
  if ("EventSource" in window) {
    const stream = new EventSource("/console/api/approval-events", { withCredentials: true });
    stream.addEventListener("approval", (event) => {
      try { applySnapshot(JSON.parse(event.data)); } catch (_) {}
    });
    stream.addEventListener("logout", () => {
      stream.close();
      location.assign("/console/login");
    });
    window.addEventListener("pagehide", () => {
      stream.close();
      for (const id of state.notices.keys()) closeNotice(id);
    });
    // Native EventSource handles transport reconnects and a fresh initial snapshot.
  }
  setInterval(tick, 500); // Display-only countdown; no background HTTP polling.
})();
