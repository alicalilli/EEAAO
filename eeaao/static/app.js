"use strict";
// All text reaches the page through textContent (never innerHTML), so scope
// entries, notes and anything a bot brings back from a target can never run
// as markup in this app.

const $ = (selector, root = document) => root.querySelector(selector);

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (key === "checked" || key === "disabled" || key === "open") node[key] = !!value;
    else if (key === "value") node.value = value;
    else if (value !== false && value != null) node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child != null && child !== false) node.append(child);
  }
  return node;
}

// replaceChildren that skips false/null, so `cond && h(...)` can be passed.
function fill(node, ...children) {
  node.replaceChildren(...children.flat().filter((c) => c != null && c !== false && c !== ""));
}

async function api(method, path, body) {
  const response = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (response.status === 204) return null;
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const error = new Error("Request failed");
    error.detail = data && data.detail;
    throw error;
  }
  return data;
}

function when(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { dateStyle: "short", timeStyle: "medium" });
}

const state = {
  programs: [], selectedId: null, editingId: null, catalog: [], tab: "overview",
  poll: null, showExcluded: false, showDismissed: false, showStale: false,
  inventory: { kind: "", q: "", offset: 0 }, log: { offset: 0 },
};

const TABS = [
  ["overview", "Scope"], ["bots", "Bots"], ["findings", "Findings"],
  ["leads", "Leads"], ["inventory", "Inventory"], ["log", "Request log"],
];

// ---------- program list ----------

function automationBadge(program) {
  return program.automation_allowed
    ? h("span", { class: "badge ok" }, "Automation allowed")
    : h("span", { class: "badge warn" }, "Manual only");
}

function renderList() {
  const list = $("#list");
  list.replaceChildren();
  if (!state.programs.length) {
    list.append(h("div", { class: "empty" },
      "No programs yet. Add one to set up its scope."));
    return;
  }
  for (const program of state.programs) {
    list.append(h("button", {
      class: "card",
      "aria-current": program.id === state.selectedId ? "true" : null,
      onclick: () => select(program.id),
    },
      h("span", { class: "name" }, program.name),
      h("span", { class: "meta" },
        `${program.in_rules.length} in scope · ${program.out_rules.length} out of scope · ${program.rate_limit} req/s`),
      automationBadge(program)));
  }
}

// ---------- program detail ----------

function chips(rules, emptyText) {
  if (!rules.length) return h("p", { class: "muted" }, emptyText);
  return h("ul", { class: "chips mono" }, rules.map((rule) => h("li", {}, rule)));
}

function currentProgram() {
  return state.programs.find((p) => p.id === state.selectedId);
}

function renderDetail() {
  stopPolling();
  const detail = $("#detail");
  const program = currentProgram();
  if (!program) {
    detail.replaceChildren(h("div", { class: "empty" },
      state.programs.length ? "Select a program to see its scope." : ""));
    return;
  }
  const headerNames = Object.keys(program.headers);
  const body = h("div", { class: "tab-body" });
  const tabs = h("div", { class: "tabs", role: "tablist" }, TABS.map(([id, label]) =>
    h("button", {
      role: "tab", "data-tab": id, "aria-selected": state.tab === id ? "true" : "false",
      onclick: () => { state.tab = id; renderDetail(); },
    }, label)));

  detail.replaceChildren(h("div", { class: "panel" },
    h("div", { class: "panel-head" },
      h("h2", {}, program.name),
      h("div", { class: "buttons" },
        h("button", { onclick: () => openForm(program) }, "Edit"),
        h("button", { class: "danger", onclick: () => remove(program) }, "Delete"))),
    h("div", { class: "facts" },
      automationBadge(program),
      h("span", {}, `${program.rate_limit} requests/second`),
      h("span", {}, headerNames.length
        ? `Sends header: ${headerNames.join(", ")}` : "No required headers"),
      program.excluded_types.length > 0 &&
        h("span", {}, `${program.excluded_types.length} excluded bug types`),
      program.url && h("a", { href: program.url, target: "_blank", rel: "noopener noreferrer" },
        "Open program page")),
    program.scope_errors.length > 0 && h("p", { class: "error" },
      "Some scope entries cannot be read, so nothing is allowed. Edit the program to fix them."),
    tabs, body));

  const render = {
    overview: renderOverview, bots: renderBots, findings: (p, b) => renderFindings(p, b, "finding"),
    leads: (p, b) => renderFindings(p, b, "lead"), inventory: renderInventory, log: renderLog,
  }[state.tab];
  render(program, body);
  // Mark the Bots tab while a run is going, whichever tab is open.
  if (state.tab !== "bots") {
    api("GET", `/api/programs/${program.id}/runs`)
      .then((runs) => setTabBusy(runs.active != null)).catch(() => {});
  }
}

function renderOverview(program, body) {
  const input = h("textarea", {
    rows: 4, spellcheck: "false", "aria-label": "Targets to check",
    placeholder: "Paste hosts or URLs, one per line",
  });
  const results = h("ul", { class: "results" });
  const summary = h("span", { class: "muted" });

  async function runCheck() {
    const targets = input.value.split(/\r?\n/).filter((line) => line.trim());
    if (!targets.length) return;
    try {
      const data = await api("POST", `/api/programs/${program.id}/scope-check`, { targets });
      const allowed = data.results.filter((r) => r.allowed).length;
      summary.textContent = `${allowed} in scope, ${data.results.length - allowed} refused`;
      results.replaceChildren(...data.results.map((r) => {
        let label = "Refused", tone = "no";
        if (r.allowed && r.automated) { label = "In scope"; tone = "ok"; }
        else if (r.allowed) { label = "In scope · manual only"; tone = "warn"; }
        return h("li", {},
          h("span", { class: `badge ${tone}` }, label),
          h("span", { class: "target mono" }, r.target),
          h("span", { class: "why" }, r.reason + (r.rule ? ` Rule: ${r.rule}` : "")));
      }));
    } catch (error) {
      summary.textContent = "Check failed.";
    }
  }

  fill(body, 
    h("div", { class: "scope-cols" },
      h("div", {}, h("h3", {}, "In scope"), chips(program.in_rules, "Nothing in scope.")),
      h("div", {}, h("h3", {}, "Out of scope"), chips(program.out_rules, "No exclusions."))),
    program.notes && h("div", {}, h("h3", {}, "Notes"), h("p", { class: "notes" }, program.notes)),
    h("h3", {}, "Scope check"),
    h("div", { class: "checker" },
      input,
      h("div", { class: "row" },
        h("button", { class: "primary", onclick: runCheck }, "Check targets"), summary),
      results));
}

// ---------- bots tab ----------

const RECON_OPTIONS = [
  ["crawl_pages_per_host", "Crawler: pages per host", 40],
  ["crawl_max_pages", "Crawler: pages in total", 300],
  ["crawl_depth", "Crawler: link depth", 3],
  ["crawl_max_js", "Crawler: JavaScript files", 150],
  ["archive_limit", "Archive: URLs per domain", 50000],
  ["github_max_queries", "GitHub: searches per run", 10],
];

function stopPolling() {
  if (state.poll) clearTimeout(state.poll);
  state.poll = null;
}

async function renderBots(program, body) {
  const runsBox = h("div", { class: "runs" });
  const live = h("div", { class: "live" });
  const departments = h("div", { class: "departments" });
  fill(body, 
    !program.automation_allowed && h("p", { class: "error" },
      "Automated scanning is off for this program, so no bot can run. Turn it on in Edit only if the program policy allows automated tools."),
    live, departments, h("h3", {}, "Recent runs"), runsBox);

  let runs;
  try {
    runs = await api("GET", `/api/programs/${program.id}/runs`);
  } catch (error) {
    runsBox.textContent = "Could not load runs.";
    return;
  }
  const busy = runs.active != null;
  const cards = {};

  for (const dept of state.catalog) {
    const boxes = [];
    const optionInputs = {};
    const marks = {};
    const list = h("ul", { class: "bots" }, dept.bots.map((bot) => {
      const box = h("input", { type: "checkbox", checked: bot.built, disabled: !bot.built,
                               "data-bot": bot.id });
      if (bot.built) boxes.push(box);
      marks[bot.id] = h("span", { class: "bot-mark", "aria-live": "polite" });
      return h("li", {},
        h("label", { class: "check" }, box,
          h("span", {}, h("strong", {}, bot.name), " ", marks[bot.id], " ",
            !bot.built && h("span", { class: "badge" }, "Planned"),
            h("span", { class: "hint" }, bot.does))));
    }));
    const error = h("div", { class: "error", role: "alert" });
    let extra = null;
    if (dept.id === "recon") {
      extra = h("details", { class: "options" }, h("summary", {}, "Limits"),
        h("div", { class: "option-grid" }, RECON_OPTIONS.map(([key, label, value]) => {
          const input = h("input", { type: "number", min: "0", value: String(value) });
          optionInputs[key] = input;
          return h("label", {}, label, input);
        }), (() => {
          const box = h("input", { type: "checkbox", checked: true });
          optionInputs.crawl_respect_robots = box;
          return h("label", { class: "check" }, box, h("span", {}, "Crawler follows robots.txt"));
        })()));
    }
    if (dept.id === "content") {
      const osv = h("input", { type: "checkbox", checked: true });
      const maps = h("input", { type: "number", min: "0", value: "50" });
      optionInputs.library_osv = osv;
      optionInputs.sourcemap_max = maps;
      extra = h("details", { class: "options" }, h("summary", {}, "Options"),
        h("div", { class: "option-grid" },
          h("label", {}, "Source maps to fetch at most", maps),
          h("label", { class: "check" }, osv, h("span", {}, "Look up library versions in OSV.dev",
            h("span", { class: "hint" }, "Sends library names and versions (not your target) to api.osv.dev.")))));
    }
    if (dept.id === "thirdparty") {
      const max = h("input", { type: "number", min: "0", value: "200" });
      optionInputs.thirdparty_max_domains = max;
      extra = h("details", { class: "options" }, h("summary", {}, "Options"),
        h("div", { class: "option-grid" }, h("label", {}, "Linked domains to look up at most", max)));
    }
    if (dept.id === "tls") {
      const box = h("input", { type: "checkbox", checked: true });
      optionInputs.tls_legacy_probe = box;
      extra = h("details", { class: "options" }, h("summary", {}, "Options"),
        h("label", { class: "check" }, box, h("span", {},
          "Check whether TLS 1.0 and 1.1 are still accepted",
          h("span", { class: "hint" },
            "Two extra standard handshakes per HTTPS endpoint, like an old browser connecting."))));
    }
    const runButton = h("button", { class: "primary", disabled: busy || !program.automation_allowed },
      `Run ${dept.name}`);
    const progress = h("div", { class: "dept-run" });
    const section = h("section", { class: "dept" },
      h("div", { class: "dept-head" },
        h("div", {}, h("h4", {}, dept.name), h("p", { class: "hint" }, dept.summary)),
        dept.runnable ? runButton : h("span", { class: "badge" }, "Coming next")),
      list, extra, error, progress);
    cards[dept.id] = { dept, section, runButton, progress, marks };
    runButton.addEventListener("click", async () => {
      const bots = boxes.filter((b) => b.checked).map((b) => b.dataset.bot);
      const options = {};
      for (const [key, input] of Object.entries(optionInputs)) {
        options[key] = input.type === "checkbox" ? input.checked : Number(input.value);
      }
      error.textContent = "";
      // React at once, before the server answers.
      setRunButtons(cards, true);
      runButton.replaceChildren(h("span", { class: "spinner" }), " Starting…");
      runbarStarting(program, dept.name);
      try {
        const run = await api("POST", `/api/programs/${program.id}/runs`,
                              { department: dept.id, bots, options });
        trackRun(program, run.id);
        followRun(program, run.id, cards, runsBox);
      } catch (e) {
        setRunButtons(cards, false, program);
        error.textContent = typeof e.detail === "string" ? e.detail : "Could not start the run.";
        runbarFailed(`${dept.name} did not start: ${error.textContent}`);
      }
    });
    departments.append(section);
  }

  const drawRuns = (list) => runsBox.replaceChildren(list.length
    ? h("ul", { class: "run-list" }, list.map((run) =>
      h("li", {},
        h("span", { class: `badge ${RUN_TONE[run.status] || "no"}` }, run.status),
        h("span", {}, `${run.department} · ${run.bots.length} bots`),
        h("span", { class: "muted" }, when(run.started_at)),
        h("button", { onclick: () => { showRun(program, run.id, live); live.scrollIntoView({ block: "nearest" }); } },
          "Show log"))))
    : h("p", { class: "muted" }, "No runs yet."));
  runsBox.redraw = async () => {
    try {
      drawRuns((await api("GET", `/api/programs/${program.id}/runs`)).runs);
    } catch (e) { /* the list simply stays as it was */ }
  };
  drawRuns(runs.runs);

  // A run that was already going when this tab opened: pick it up.
  if (busy) followRun(program, runs.active, cards, runsBox);
}

const RUN_TONE = { done: "ok", running: "warn" };

function setRunButtons(cards, disabled, program) {
  for (const card of Object.values(cards)) {
    card.runButton.disabled = disabled || (program && !program.automation_allowed);
    if (!disabled) card.runButton.textContent = `Run ${card.dept.name}`;
  }
}

function setTabBusy(busy) {
  const tab = [...document.querySelectorAll(".tabs button")].find((b) => b.dataset.tab === "bots");
  if (tab) tab.classList.toggle("busy", busy);
}

// Shows a run inside the card of its department: spinner, current bot, a tick
// per finished bot, live log, and a summary that stays when it ends.
async function followRun(program, runId, cards, runsBox) {
  stopPolling();
  setRunButtons(cards, true);
  setTabBusy(true);
  let card = null, after = 0, current = "", lastLine = "";
  const spinner = h("span", { class: "spinner" });
  const headline = h("strong", {});
  const sub = h("span", { class: "muted" });
  const events = h("ol", { class: "events mono" });
  const stop = h("button", { class: "danger", onclick: async () => {
    stop.disabled = true;
    stop.textContent = "Stopping…";
    await api("POST", `/api/runs/${runId}/stop`);
  } }, "Stop");
  const head = h("div", { class: "row run-head", role: "status" }, spinner, headline, sub, stop);
  const result = h("div", { class: "run-result" });
  const log = h("details", { class: "run-log", open: true }, h("summary", {}, "Live log"), events);

  const tick = async () => {
    let run;
    try {
      run = await api("GET", `/api/runs/${runId}?after=${after}`);
    } catch (e) {
      state.poll = setTimeout(tick, 3000);  // the app may be restarting: keep trying
      return;
    }
    if (!card) {
      card = cards[run.department];
      if (!card) return;
      for (const other of Object.values(cards)) other.section.classList.remove("running");
      card.section.classList.add("running");
      card.runButton.replaceChildren(h("span", { class: "spinner" }), " Running…");
      for (const [bot, mark] of Object.entries(card.marks)) {
        mark.className = "bot-mark";
        mark.textContent = run.bots.includes(bot) ? "waiting" : "";
        if (run.bots.includes(bot)) mark.classList.add("wait");
      }
      card.progress.replaceChildren(h("div", { class: "run-panel" }, head, result, log));
      card.progress.scrollIntoView({ block: "nearest", behavior: "smooth" });
    }
    for (const event of run.events) {
      after = event.id;
      events.append(h("li", { class: `ev ${event.level}` },
        h("span", { class: "muted" }, new Date(event.at).toLocaleTimeString()), " ",
        event.bot && h("strong", {}, event.bot), " ", event.message));
      const mark = card.marks[event.bot];
      if (mark && event.message === "Started") {
        current = event.bot;
        lastLine = "";
        mark.className = "bot-mark run";
        mark.replaceChildren(h("span", { class: "spinner small" }), " running");
      } else if (mark && event.message.startsWith("Finished")) {
        mark.className = "bot-mark done";
        mark.textContent = "✓ done";
      } else if (mark && /^(Crashed|Stopped)/.test(event.message)) {
        mark.className = "bot-mark fail";
        mark.textContent = "✗ failed";
      } else if (event.bot) {
        lastLine = event.message;
      }
    }
    events.scrollTop = events.scrollHeight;
    const elapsed = duration(Date.now() - Date.parse(run.started_at));
    const botName = (card.dept.bots.find((b) => b.id === current) || {}).name || "Starting";
    const position = run.bots.indexOf(current) + 1;

    if (run.status === "running") {
      headline.textContent = `${card.dept.name} is running: ${botName}`
        + (position ? ` (${position} of ${run.bots.length})` : "");
      sub.textContent = elapsed + (lastLine ? ` · ${lastLine}` : "");
      state.poll = setTimeout(tick, 1000);
      return;
    }
    // Finished: leave a clear result where the user clicked.
    const totals = Object.values(run.summary || {}).reduce((sum, s) => ({
      findings: sum.findings + (s.findings_new || 0), leads: sum.leads + (s.leads_new || 0),
      assets: sum.assets + (s.assets_new || 0), retired: sum.retired + (s.retired || 0) }),
      { findings: 0, leads: 0, assets: 0, retired: 0 });
    spinner.remove();
    stop.remove();
    const ok = run.status === "done";
    headline.textContent = ok ? `${card.dept.name} finished`
      : `${card.dept.name} ${run.status === "stopped" ? "was stopped" : "ended with errors"}`;
    sub.textContent = `${run.bots.length} bots`;
    head.prepend(h("span", { class: `badge ${ok ? "ok" : "no"}` }, ok ? "Done" : run.status));
    const go = (tab) => { state.tab = tab; renderDetail(); };
    result.replaceChildren(
      h("span", {}, `${totals.findings} new finding${totals.findings === 1 ? "" : "s"}, `
        + `${totals.leads} new lead${totals.leads === 1 ? "" : "s"}, `
        + `${totals.assets} new inventory item${totals.assets === 1 ? "" : "s"}`
        + (totals.retired ? `, ${totals.retired} earlier result${totals.retired === 1 ? "" : "s"} no longer seen` : "")),
      h("span", { class: "buttons" },
        h("button", { onclick: () => go("findings") }, "View findings"),
        h("button", { onclick: () => go("leads") }, "View leads"),
        h("button", { onclick: () => go("inventory") }, "View inventory")));
    log.open = !ok;
    for (const mark of Object.values(card.marks)) {
      if (mark.classList.contains("wait") || mark.classList.contains("run")) {
        mark.className = "bot-mark";
        mark.textContent = ok ? "" : "not run";
      }
    }
    card.section.classList.remove("running");
    card.section.classList.add("finished");
    setRunButtons(cards, false, program);
    setTabBusy(false);
    if (runsBox.redraw) runsBox.redraw();
  };
  tick();
}

// A past run's log, shown at the top of the tab.
async function showRun(program, runId, box) {
  let run;
  try {
    run = await api("GET", `/api/runs/${runId}`);
  } catch (e) {
    return;
  }
  box.replaceChildren(h("div", { class: "run-panel" },
    h("div", { class: "row" }, h("strong", {}, `Run #${runId}: ${run.department}`),
      h("span", { class: `badge ${RUN_TONE[run.status] || "no"}` }, run.status),
      h("span", { class: "muted" }, when(run.started_at)),
      h("button", { onclick: () => box.replaceChildren() }, "Close")),
    h("ol", { class: "events mono" }, run.events.map((event) =>
      h("li", { class: `ev ${event.level}` },
        h("span", { class: "muted" }, new Date(event.at).toLocaleTimeString()), " ",
        event.bot && h("strong", {}, event.bot), " ", event.message)))));
}

// ---------- findings and leads ----------

const SEV_TONE = { high: "no", medium: "warn", low: "", info: "" };

function evidenceList(evidence) {
  const show = (value) => typeof value === "string" ? value
    : Array.isArray(value) ? value.map(show).join("\n")
    : value && typeof value === "object"
      ? Object.entries(value).map(([k, v]) => `${k}: ${show(v)}`).join("\n")
      : String(value);
  const entries = Object.entries(evidence || {}).filter(([, v]) => v != null && v !== "");
  if (!entries.length) return null;
  return h("dl", { class: "evidence" }, entries.flatMap(([key, value]) => [
    h("dt", {}, key.replace(/_/g, " ")),
    h("dd", { class: "mono" }, show(value)),
  ]));
}

async function renderFindings(program, body, kind) {
  let items;
  try {
    items = await api("GET", `/api/programs/${program.id}/findings?kind=${kind}`);
  } catch (e) {
    fill(body, h("p", { class: "error" }, "Could not load."));
    return;
  }
  const excludedCount = items.filter((i) => i.excluded).length;
  const dismissedCount = items.filter((i) => i.status === "dismissed").length;
  const staleCount = items.filter((i) => i.status === "stale").length;
  const visible = items.filter((i) => (state.showExcluded || !i.excluded) &&
                                      (state.showDismissed || i.status !== "dismissed") &&
                                      (state.showStale || i.status !== "stale"));
  const toggles = h("div", { class: "row" },
    h("label", { class: "check inline" }, h("input", { type: "checkbox", checked: state.showExcluded,
      onchange: (e) => { state.showExcluded = e.target.checked; renderDetail(); } }),
      h("span", {}, `Show excluded (${excludedCount})`)),
    h("label", { class: "check inline" }, h("input", { type: "checkbox", checked: state.showDismissed,
      onchange: (e) => { state.showDismissed = e.target.checked; renderDetail(); } }),
      h("span", {}, `Show dismissed (${dismissedCount})`)),
    h("label", { class: "check inline", title: "Results a later run of the same bot did not find again" },
      h("input", { type: "checkbox", checked: state.showStale,
        onchange: (e) => { state.showStale = e.target.checked; renderDetail(); } }),
      h("span", {}, `Show no longer seen (${staleCount})`)),
    h("span", { class: "muted" }, `${visible.length} shown`));

  const intro = kind === "lead"
    ? "Leads are candidates for your own manual work. Nothing here was tested."
    : "Findings come from passive observation and are unverified until you confirm them.";
  const setStatus = async (item, status) => {
    await api("PATCH", `/api/findings/${item.id}`, { status });
    renderDetail();
  };
  fill(body, h("p", { class: "muted" }, intro), toggles,
    visible.length ? h("div", { class: "cards" }, visible.map((item) =>
      h("article", { class: `finding ${item.excluded || item.status === "dismissed" || item.status === "stale" ? "dim" : ""}` },
        h("div", { class: "row" },
          h("span", { class: `badge ${SEV_TONE[item.severity] || ""}` }, item.severity),
          h("span", { class: "badge" }, item.type_label),
          item.excluded && h("span", { class: "badge no" }, "Excluded by program"),
          item.status === "stale" && h("span", { class: "badge" }, "no longer seen"),
          item.status !== "new" && item.status !== "stale" && h("span", { class: "badge ok" }, item.status)),
        h("h4", {}, item.title),
        h("p", { class: "mono target" }, item.target),
        item.detail && h("p", {}, item.detail),
        evidenceList(item.evidence),
        h("div", { class: "row foot" },
          h("span", { class: "muted" },
            `${item.department} / ${item.bot} · seen ${item.hits}× · first ${when(item.first_seen)} · last ${when(item.last_seen)}`),
          h("span", { class: "buttons" },
            item.status !== "reviewed" && h("button", { onclick: () => setStatus(item, "reviewed") }, "Mark reviewed"),
            item.status !== "dismissed" && h("button", { onclick: () => setStatus(item, "dismissed") }, "Dismiss"),
            item.status !== "new" && h("button", { onclick: () => setStatus(item, "new") }, "Reset"))))))
    : h("p", { class: "empty" }, kind === "lead" ? "No leads to show." : "No findings to show."));
}

// ---------- inventory ----------

const KIND_LABELS = {
  host: "Hosts", dns: "DNS records", site: "Live sites", url: "URLs", param: "Parameters",
  form: "Forms", js: "JavaScript", publicfile: "Public files", external: "External links",
  bucket: "Buckets", github: "GitHub results", cookie: "Cookies", tls: "TLS endpoints", endpoint: "JS endpoints",
  library: "Libraries", sourcemap: "Source maps", email: "Mail domains",
  linkdomain: "Linked domains", social: "Social links",
};

function summarize(kind, data) {
  const parts = [];
  if (data.sources) parts.push("from " + Object.keys(data.sources).join(", "));
  if (kind === "host") {
    if (data.resolves === false) parts.push("does not resolve");
    if (data.ips && data.ips.length) parts.push(data.ips.join(" "));
    if (data.cname && data.cname.length) parts.push("CNAME " + data.cname.join(" → "));
    if (data.live === true) parts.push("live");
    if (data.tech) parts.push(Object.keys(data.tech).join(", "));
  } else if (kind === "dns") {
    for (const [type, values] of Object.entries(data.records || {})) {
      if (values.length) parts.push(`${type}: ${values.join(" | ")}`);
    }
    if (data.status && data.status !== "NOERROR") parts.push(data.status);
  } else if (kind === "site") {
    parts.push(String(data.status));
    if (data.title) parts.push(`"${data.title}"`);
    if (data.final_url) parts.push("→ " + data.final_url);
    if (data.tech && data.tech.length) parts.push(data.tech.join(", "));
    if (data.blocked_redirect) parts.push("redirect out of scope not followed: " + data.blocked_redirect);
  } else if (kind === "tls") {
    if (data.error) parts.push("no handshake: " + data.error);
    if (data.negotiated || data.version) parts.push(data.negotiated || `${data.version} ${data.cipher}`);
    if (data.verified != null) parts.push(data.verified ? "trusted" : "NOT trusted: " + (data.verify_error || ""));
    if (data.subject) parts.push("cert " + data.subject);
    if (data.issuer) parts.push("by " + data.issuer);
    if (data.not_after) parts.push("until " + data.not_after);
    if (data.old_versions_accepted) parts.push("accepts " + data.old_versions_accepted.join(", "));
  } else if (kind === "library") {
    if (data.known_vulnerabilities != null) parts.push(`${data.known_vulnerabilities} known vulnerabilities`);
    if (data.where) parts.push("in " + Object.keys(data.where).join(", "));
  } else if (kind === "email") {
    parts.push("SPF: " + (data.spf ? data.spf.join(" | ") : "none"));
    parts.push("DMARC: " + (data.dmarc ? data.dmarc.join(" | ") : "none"));
  } else if (kind === "endpoint") {
    if (data.from) parts.push("from " + Object.keys(data.from).slice(0, 3).join(", "));
  } else if (kind === "sourcemap") {
    parts.push(`status ${data.status ?? "no answer"}`);
    if (data.sources != null) parts.push(`${data.sources} files` + (data.has_source_code ? ", with source code" : ""));
    if (data.referenced_by) parts.push("named by " + data.referenced_by);
  } else if (kind === "linkdomain") {
    parts.push(data.state || data.registry);
    if (data.state) parts.push("registry " + data.registry);
    parts.push(`${data.links} link${data.links === 1 ? "" : "s"}`);
  } else if (kind === "social") {
    parts.push(`${data.platform} ${data.handle}: ${data.status}`);
    if (data.pages) parts.push("on " + data.pages.join(", "));
  } else if (kind === "form") {
    parts.push("fields: " + Object.keys(data.inputs || {}).join(", "));
    if (data.found_on) parts.push("on " + data.found_on);
  } else {
    if (data.set_cookie) parts.push(data.set_cookie + (data.session_like ? " · session-like" : "")
      + (data.set_by_infrastructure ? ` · set by ${data.set_by_infrastructure}, not the application` : ""));
    for (const key of ["status", "kind", "title", "repo", "path", "provider", "entries", "paths", "bytes"]) {
      if (data[key] != null && data[key] !== "") parts.push(`${key}: ${data[key]}`);
    }
    if (data.archived) parts.push(`archived ${data.archived.timestamp} (${data.archived.status})`);
    if (data.fields) parts.push(Object.entries(data.fields).map(([k, v]) => `${k}: ${v.join(", ")}`).join(" · "));
  }
  return parts.join(" · ");
}

async function renderInventory(program, body) {
  const inv = state.inventory;
  const params = new URLSearchParams({ kind: inv.kind, q: inv.q, limit: 100, offset: inv.offset });
  let data;
  try {
    data = await api("GET", `/api/programs/${program.id}/assets?${params}`);
  } catch (e) {
    fill(body, h("p", { class: "error" }, "Could not load."));
    return;
  }
  const kinds = Object.keys(KIND_LABELS).filter((k) => data.counts[k]);
  const search = h("input", { type: "search", placeholder: "Filter by text", value: inv.q });
  let timer;
  search.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(() => { inv.q = search.value; inv.offset = 0; renderDetail(); }, 350);
  });
  const pick = (kind) => { inv.kind = kind; inv.offset = 0; renderDetail(); };
  fill(body, 
    h("div", { class: "kind-bar" },
      h("button", { "aria-pressed": inv.kind === "" ? "true" : "false", onclick: () => pick("") },
        `All (${Object.values(data.counts).reduce((a, b) => a + b, 0)})`),
      kinds.map((k) => h("button", { "aria-pressed": inv.kind === k ? "true" : "false",
                                     onclick: () => pick(k) }, `${KIND_LABELS[k]} (${data.counts[k]})`))),
    search,
    data.items.length ? h("ul", { class: "assets" }, data.items.map((a) => h("li", {},
      h("span", { class: "badge" }, KIND_LABELS[a.kind] || a.kind),
      h("span", { class: "mono value" }, a.value),
      h("span", { class: "why" }, summarize(a.kind, a.data)))))
      : h("p", { class: "empty" }, "Nothing in the inventory yet. Run the Recon department."),
    pager(data.total, inv.offset, 100, (offset) => { inv.offset = offset; renderDetail(); }));
}

function pager(total, offset, size, go) {
  if (total <= size) return null;
  return h("div", { class: "row pager" },
    h("button", { disabled: offset === 0, onclick: () => go(Math.max(0, offset - size)) }, "Previous"),
    h("span", { class: "muted" }, `${offset + 1}–${Math.min(total, offset + size)} of ${total}`),
    h("button", { disabled: offset + size >= total, onclick: () => go(offset + size) }, "Next"));
}

// ---------- request log ----------

async function renderLog(program, body) {
  let data;
  try {
    data = await api("GET", `/api/programs/${program.id}/requests?limit=100&offset=${state.log.offset}`);
  } catch (e) {
    fill(body, h("p", { class: "error" }, "Could not load."));
    return;
  }
  fill(body, 
    h("p", { class: "muted" }, "Every request bots made: to targets, to passive sources, and DNS lookups."),
    h("div", { class: "table-wrap" }, h("table", { class: "log mono" },
      h("thead", {}, h("tr", {}, ["Time", "Bot", "Kind", "Method", "URL / name", "Status", "ms", "Bytes", "Note"]
        .map((t) => h("th", {}, t)))),
      h("tbody", {}, data.items.map((r) => h("tr", { class: r.error ? "err" : "" },
        h("td", {}, new Date(r.at).toLocaleTimeString()), h("td", {}, r.bot), h("td", {}, r.kind),
        h("td", {}, r.method), h("td", { class: "url" }, r.url), h("td", {}, r.status ?? ""),
        h("td", {}, r.duration_ms ?? ""), h("td", {}, r.bytes ?? ""), h("td", {}, r.error || "")))))),
    pager(data.total, state.log.offset, 100, (offset) => { state.log.offset = offset; renderDetail(); }));
}

// ---------- selection and loading ----------

function select(id) {
  if (state.selectedId !== id) {
    state.inventory = { kind: "", q: "", offset: 0 };
    state.log = { offset: 0 };
  }
  state.selectedId = id;
  renderList();
  renderDetail();
}

async function load() {
  state.programs = await api("GET", "/api/programs");
  if (!state.programs.some((p) => p.id === state.selectedId)) {
    state.selectedId = state.programs.length ? state.programs[0].id : null;
  }
  renderList();
  renderDetail();
}

async function remove(program) {
  if (!confirm(`Delete "${program.name}", its scope and everything the bots collected? This cannot be undone.`)) return;
  await api("DELETE", `/api/programs/${program.id}`);
  await load();
}

// ---------- add / edit form ----------

const dialog = $("#form-dialog");
const form = $("#form");

function headersToText(headers) {
  return Object.entries(headers).map(([name, value]) => `${name}: ${value}`).join("\n");
}

function textToHeaders(text) {
  const headers = {};
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const colon = line.indexOf(":");
    if (colon < 1) throw new Error(`Header line needs "Name: value": ${line.trim()}`);
    headers[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
  }
  return headers;
}

function showErrors(box, message, items = []) {
  box.replaceChildren();
  if (message) box.append(message);
  if (items.length) box.append(h("ul", {}, items.map((item) => h("li", {}, item))));
}

function describeScopeErrors(errors) {
  return errors.map((e) =>
    `${e.list === "in_scope" ? "In scope" : "Out of scope"}: "${e.entry}" - ${e.error}`);
}

let validateTimer;
function validateScopeSoon() {
  clearTimeout(validateTimer);
  validateTimer = setTimeout(async () => {
    const box = $("#scope-feedback");
    try {
      const data = await api("POST", "/api/scope/validate", {
        in_scope: form.in_scope.value, out_of_scope: form.out_of_scope.value,
      });
      box.replaceChildren(
        `${data.in_rules.length} in-scope and ${data.out_rules.length} out-of-scope entries understood.`);
      if (data.scope_errors.length) {
        box.append(h("ul", { class: "bad" },
          describeScopeErrors(data.scope_errors).map((text) => h("li", {}, text))));
      }
    } catch (error) {
      box.replaceChildren();
    }
  }, 300);
}

function renderExclusions(selected) {
  const chosen = new Set(selected);
  const count = () => {
    const n = form.querySelectorAll("input[data-type]:checked").length;
    $("#exclusion-count").textContent = n ? `${n} excluded` : "none excluded";
  };
  $("#exclusion-list").replaceChildren(...state.catalog
    .filter((dept) => dept.bots.some((b) => b.types.length))
    .map((dept) => h("fieldset", {}, h("legend", {}, dept.name),
      dept.bots.flatMap((bot) => bot.types).map((type) => h("label", { class: "check inline" },
        h("input", { type: "checkbox", "data-type": type.id, checked: chosen.has(type.id),
                     onchange: count }),
        h("span", {}, type.label, " ", h("span", { class: "hint inline-hint" },
          type.kind === "lead" ? "lead" : "")))))));
  count();
}

function openForm(program) {
  state.editingId = program ? program.id : null;
  $("#form-title").textContent = program ? "Edit program" : "Add program";
  form.reset();
  showErrors($("#form-error"), "");
  if (program) {
    form.name.value = program.name;
    form.url.value = program.url;
    form.in_scope.value = program.in_scope;
    form.out_of_scope.value = program.out_of_scope;
    form.rate_limit.value = program.rate_limit;
    form.headers.value = headersToText(program.headers);
    form.automation_allowed.checked = program.automation_allowed;
    form.notes.value = program.notes;
  }
  renderExclusions(program ? program.excluded_types : []);
  validateScopeSoon();
  dialog.showModal();
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorBox = $("#form-error");
  let body;
  try {
    body = {
      name: form.name.value,
      url: form.url.value,
      in_scope: form.in_scope.value,
      out_of_scope: form.out_of_scope.value,
      rate_limit: Number(form.rate_limit.value),
      headers: textToHeaders(form.headers.value),
      automation_allowed: form.automation_allowed.checked,
      notes: form.notes.value,
      excluded_types: [...form.querySelectorAll("input[data-type]:checked")]
        .map((box) => box.dataset.type),
    };
  } catch (error) {
    showErrors(errorBox, error.message);
    return;
  }
  try {
    const saved = state.editingId
      ? await api("PUT", `/api/programs/${state.editingId}`, body)
      : await api("POST", "/api/programs", body);
    state.selectedId = saved.id;
    dialog.close();
    await load();
  } catch (error) {
    const detail = error.detail;
    if (Array.isArray(detail)) {
      showErrors(errorBox, "Please fix:", detail.map((d) =>
        `${d.loc[d.loc.length - 1]}: ${d.msg.replace(/^Value error, /, "")}`));
    } else if (detail && detail.message) {
      showErrors(errorBox, detail.message, describeScopeErrors(detail.scope_errors || []));
    } else {
      showErrors(errorBox, typeof detail === "string" ? detail : "Could not save the program.");
    }
  }
});

form.in_scope.addEventListener("input", validateScopeSoon);
form.out_of_scope.addEventListener("input", validateScopeSoon);
$("#cancel").addEventListener("click", () => dialog.close());
$("#add").addEventListener("click", () => openForm(null));

// ---------- settings ----------

const settingsDialog = $("#settings-dialog");
const settingsForm = $("#settings-form");

async function showTokenState() {
  const s = await api("GET", "/api/settings");
  $("#token-state").textContent = s.github_token_set
    ? "A token is saved."
    : s.github_token_from_env ? "Using GITHUB_TOKEN from the environment." : "No token saved.";
}

$("#settings-btn").addEventListener("click", async () => {
  settingsForm.reset();
  $("#settings-error").textContent = "";
  await showTokenState();
  settingsDialog.showModal();
});
$("#settings-close").addEventListener("click", () => settingsDialog.close());
$("#token-clear").addEventListener("click", async () => {
  await api("DELETE", "/api/settings/github-token");
  await showTokenState();
});
settingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("PUT", "/api/settings/github-token", { token: settingsForm.token.value.trim() });
    settingsForm.reset();
    await showTokenState();
  } catch (e) {
    $("#settings-error").textContent = "That does not look like a GitHub token.";
  }
});

// ---------- run status bar (top of the window, every tab) ----------

const runbar = { runId: null, timer: null, after: 0, current: "", hideTimer: null };

// The bar's slot is in index.html, but a browser may still show a page saved
// before the bar existed. Create the slot then, instead of failing.
function runbarEl() {
  let bar = $("#runbar");
  if (!bar) {
    bar = h("div", { id: "runbar", class: "runbar", role: "status", "aria-live": "polite" });
    bar.hidden = true;
    const header = document.querySelector("header.top");
    if (header) header.after(bar);
    else document.body.prepend(bar);
  }
  return bar;
}

function duration(ms) {
  const total = Math.max(0, Math.round(ms / 1000));
  const h_ = Math.floor(total / 3600), m = Math.floor((total % 3600) / 60), s = total % 60;
  return h_ ? `${h_}h ${m}m` : m ? `${m}m ${String(s).padStart(2, "0")}s` : `${s}s`;
}

function deptName(id) {
  return (state.catalog.find((d) => d.id === id) || {}).name || id;
}

function goToBots(programId) {
  state.tab = "bots";
  if (state.selectedId !== programId) select(programId);
  else renderDetail();
}

// Shown the instant Run is pressed, before the server has answered.
function runbarStarting(program, departmentName) {
  const bar = runbarEl();
  clearTimeout(runbar.hideTimer);
  bar.hidden = false;
  bar.className = "runbar running";
  bar.replaceChildren(h("span", { class: "spinner" }),
    h("strong", {}, `Starting ${departmentName}`), h("span", { class: "muted" }, program.name));
}

function runbarFailed(message) {
  const bar = runbarEl();
  bar.className = "runbar failed";
  bar.replaceChildren(h("strong", {}, message),
    h("button", { onclick: () => { bar.hidden = true; } }, "Close"));
}

function trackRun(program, runId) {
  if (runbar.runId === runId) return;
  clearTimeout(runbar.timer);
  clearTimeout(runbar.hideTimer);
  Object.assign(runbar, { runId, after: 0, current: "" });
  const bar = runbarEl();
  const tick = async () => {
    if (runbar.runId !== runId) return;
    let run;
    try {
      run = await api("GET", `/api/runs/${runId}?after=${runbar.after}`);
    } catch (e) {
      runbar.timer = setTimeout(tick, 3000);  // app restarting: keep trying
      return;
    }
    for (const event of run.events) {
      runbar.after = event.id;
      if (event.bot && event.message === "Started") runbar.current = event.bot;
    }
    const dept = state.catalog.find((d) => d.id === run.department);
    const bot = dept && dept.bots.find((b) => b.id === runbar.current);
    const position = run.bots.indexOf(runbar.current) + 1;
    const startedAt = Date.parse(run.started_at);
    const show = h("button", { onclick: () => goToBots(program.id) }, "Show");
    bar.hidden = false;
    if (run.status === "running") {
      bar.className = "runbar running";
      bar.replaceChildren(
        h("span", { class: "spinner" }),
        h("strong", {}, `${deptName(run.department)} is running`),
        h("span", {}, bot ? `${bot.name} (${position} of ${run.bots.length})` : "starting…"),
        h("span", { class: "muted" }, `${program.name} · ${duration(Date.now() - startedAt)}`),
        show);
      runbar.timer = setTimeout(tick, 1500);
      return;
    }
    const totals = Object.values(run.summary || {}).reduce((sum, s) => ({
      findings: sum.findings + (s.findings_new || 0), leads: sum.leads + (s.leads_new || 0) }),
      { findings: 0, leads: 0 });
    const ok = run.status === "done";
    const took = duration(Date.parse(run.finished_at || new Date().toISOString()) - startedAt);
    bar.className = `runbar ${ok ? "done" : "failed"}`;
    bar.replaceChildren(
      h("strong", {}, `${deptName(run.department)} ${ok ? "finished" : run.status === "stopped"
        ? "was stopped" : "ended with errors"}`),
      h("span", {}, `${totals.findings} new findings, ${totals.leads} new leads`),
      h("span", { class: "muted" }, `${program.name} · took ${took}`),
      show,
      h("button", { onclick: () => { bar.hidden = true; } }, "Close"));
    if (ok) runbar.hideTimer = setTimeout(() => { bar.hidden = true; }, 20000);
    setTabBusy(false);
  };
  tick();
}

// Pick up a run that is already going (page reload, run started earlier).
async function findActiveRuns() {
  for (const program of state.programs) {
    try {
      const runs = await api("GET", `/api/programs/${program.id}/runs`);
      if (runs.active != null) {
        trackRun(program, runs.active);
        return;
      }
    } catch (e) { /* ignore: the bar just stays hidden */ }
  }
}

(async () => {
  state.catalog = await api("GET", "/api/catalog");
  await load();
  findActiveRuns();
})();
