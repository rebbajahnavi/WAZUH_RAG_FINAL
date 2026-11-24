"use strict";
/* SERC enhancements: 01 alert history, 02 synchronized dataset, 03 user-friendly inputs, 04 weekly reports.
   Loaded after script.js and uses its helpers ($, $$, h, show, api, postJSON, state, showConfirm, renderResults, goStep).
   Like script.js, all server text goes in with textContent (through h()), never innerHTML. */

const VIEWS = ["analyze", "history", "report", "dataset"];
const loaded = { history: false, report: false, dataset: false };

function utcToLocal(s) {            // "2026-11-22 10:15:00" (UTC) -> the analyst's local time
  if (!s) return "";
  const d = new Date(s.replace(" ", "T") + "Z");
  return isNaN(d) ? s : d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}
const isAdmin = () => !!(state.user && state.user.role === "admin");
const sevClass = (s) => "sev-" + String(s || "unknown").toLowerCase();

/* ================================================================ navigation */
function switchView(name) {
  $$("#viewnav .vtab").forEach((b) => { const on = b.dataset.view === name; b.classList.toggle("active", on); if (on) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current"); });
  show($(".stepper"), name === "analyze"); show($("#main"), name === "analyze");
  VIEWS.slice(1).forEach((v) => show($("#view-" + v), v === name));
  if (name === "history") loadHistory(true);
  if (name === "report") loadReport();
  if (name === "dataset") loadDataset();
  window.scrollTo({ top: 0 });
}

/* ================================================================ 03 user-friendly inputs */
const FORM_FIELDS = ["description", "level", "timestamp", "agent_name", "srcip", "user", "mitre", "rule_id", "full_log"];

function clearFieldErrors() { $$("#itab-form .field-error").forEach((e) => { e.textContent = ""; show(e, false); }); $$("#itab-form .invalid").forEach((e) => e.classList.remove("invalid")); }

function showFieldErrors(errors) {
  clearFieldErrors();
  let first = null;
  for (const [field, msg] of Object.entries(errors || {})) {
    const slot = $(`#itab-form .field-error[data-for="${field}"]`), input = $("#g-" + field);
    if (slot) { slot.textContent = msg; show(slot); }
    if (input) { input.classList.add("invalid"); input.setAttribute("aria-invalid", "true"); first = first || input; }
  }
  if (first) first.focus();
}

function fillForm(fields) {
  FORM_FIELDS.forEach((f) => { const el = $("#g-" + f); if (el) el.value = fields[f] || ""; });
  clearFieldErrors(); inputError(""); $("#g-description").focus();
}

async function submitForm() {
  const btn = $("#btn-form"); inputError("");
  const body = {}; FORM_FIELDS.forEach((f) => { body[f] = $("#g-" + f).value; });
  if (body.timestamp) body.timestamp = new Date(body.timestamp).toISOString();     // local -> UTC
  btn.disabled = true; const old = btn.textContent; btn.textContent = "Checking…";
  try {
    const res = await postJSON("/api/alerts/from-form", body);
    if (!res.ok) { showFieldErrors(res.errors); inputError(res.message || "Please check the form."); return; }
    clearFieldErrors(); state.ingest = res; showConfirm();
  } catch (e) { inputError(e.message); }
  finally { btn.disabled = false; btn.textContent = old; }
}

function describePaste(text) {
  const t = text.trim();
  if (!t) return "Tip: press Ctrl+Enter (⌘+Enter on Mac) to continue.";
  if (t[0] === "{" || t[0] === "[") { try { JSON.parse(t); return "Looks like JSON. SERC will read it as a Wazuh alert."; } catch (_) { return "Looks like JSON, but it has a mistake (a missing bracket or comma?). It will be read as plain text."; } }
  const lines = t.split(/\r?\n/).filter((l) => l.trim()).length;
  return lines > 1 ? `${lines} lines found. They will be analysed together as one incident.` : "Looks like a log line. SERC will guess the details and ask you to confirm them.";
}

async function initInputs() {
  // paste tab: live hint, keyboard shortcut, clipboard button
  const ta = $("#paste-text");
  ta.addEventListener("input", () => { $("#paste-hint").textContent = describePaste(ta.value); });
  ta.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); $("#btn-paste").click(); } });
  $("#btn-clipboard").addEventListener("click", async () => {
    try { ta.value = await navigator.clipboard.readText(); ta.dispatchEvent(new Event("input")); ta.focus(); }
    catch (_) { inputError("Your browser did not allow reading the clipboard. Click in the box and press Ctrl+V instead."); }
  });

  // guided form
  $("#btn-form").addEventListener("click", submitForm);
  $("#btn-form-clear").addEventListener("click", () => { fillForm({}); inputError(""); });
  $("#guided-form").addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.tagName === "INPUT") { e.preventDefault(); submitForm(); } });
  FORM_FIELDS.forEach((f) => { const el = $("#g-" + f); if (el) el.addEventListener("input", () => { el.classList.remove("invalid"); el.removeAttribute("aria-invalid"); const s = $(`#itab-form .field-error[data-for="${f}"]`); if (s) { s.textContent = ""; show(s, false); } }); });
  try {
    const opts = await api("/api/alerts/form-options");
    $("#form-templates").replaceChildren(h("span", { class: "muted sm" }, "Start from an example:"),
      ...opts.templates.map((t) => h("button", { class: "chip-btn", type: "button", onclick: () => fillForm(t.fields) }, t.label)));
    $("#technique-list").replaceChildren(...opts.techniques.map((id) => h("option", { value: id })));
  } catch (_) { /* the form still works without templates */ }
}

/* ================================================================ 01 alert history */
const hist = { offset: 0, total: 0, items: [], busy: false, timer: null };
const HIST_PAGE = 25;

function histParams(extra = {}) {
  const p = new URLSearchParams();
  const q = $("#h-q").value.trim(), sev = $("#h-sev").value, days = $("#h-days").value;
  if (q) p.set("q", q); if (sev) p.set("severity", sev); if (days !== "0") p.set("days", days);
  if ($("#h-mine").checked) p.set("mine", "true");
  for (const [k, v] of Object.entries(extra)) p.set(k, v);
  return p;
}

async function loadHistory(reset) {
  if (hist.busy) return;
  hist.busy = true; show($("#hist-error"), false);
  if (reset) { hist.offset = 0; hist.items = []; }
  try {
    const page = await api("/api/history?" + histParams({ limit: HIST_PAGE, offset: hist.offset }));
    hist.items = hist.items.concat(page.items); hist.total = page.total; hist.offset = hist.items.length; hist.me = page.me;
    renderHistory();
  } catch (e) { if (!e.auth) { const er = $("#hist-error"); er.textContent = e.message; show(er); } }
  finally { hist.busy = false; }
  $("#h-export").href = "/api/history/export.csv?" + histParams();
}

function renderHistory() {
  const list = $("#hist-list");
  $("#hist-count").textContent = hist.total === 0 ? "" : `${hist.items.length} of ${hist.total} alert${hist.total === 1 ? "" : "s"}`;
  show($("#hist-more"), hist.items.length < hist.total);
  if (!hist.items.length) {
    const filtered = histParams().toString() !== "";
    list.replaceChildren(h("div", { class: "empty" }, h("strong", {}, filtered ? "Nothing matches those filters." : "No alerts analysed yet."),
      h("p", { class: "muted" }, filtered ? "Try clearing a filter." : "Alerts you analyse are saved here automatically."),
      filtered ? null : h("button", { class: "btn primary small", type: "button", onclick: () => switchView("analyze") }, "Analyze an alert")));
    return;
  }
  list.replaceChildren(h("div", { class: "table-wrap" }, h("table", { class: "hist-table" },
    h("thead", {}, h("tr", {}, ["Time", "Severity", "Alert", "Analyst", ""].map((t) => h("th", {}, t)))),
    h("tbody", {}, hist.items.map(histRow)))));
}

function histRow(it) {
  const mine = it.username === hist.me;
  return h("tr", {},
    h("td", { class: "nowrap" }, utcToLocal(it.submitted_at)),
    h("td", {}, h("span", { class: "badge " + sevClass(it.severity) }, it.severity + (it.level != null ? ` (${it.level})` : ""))),
    h("td", { class: "hist-desc" }, h("div", {}, it.description || "(no description)"),
      h("div", { class: "muted sm" }, [it.agent_name, it.rule_id && ("rule " + it.rule_id), it.srcip, it.mitre_ids.join(" ")].filter(Boolean).join(" · "))),
    h("td", {}, it.username || "–"),
    h("td", { class: "nowrap row-actions" },
      h("button", { class: "btn small", type: "button", onclick: () => openHistory(it.id) }, "Open"),
      (mine || isAdmin()) ? h("button", { class: "btn small danger", type: "button", "aria-label": "Delete this entry", title: "Delete this entry", onclick: () => deleteHistory(it) }, "Delete") : null));
}

async function deleteHistory(it) {
  if (!confirm("Delete this entry from the history?\n\nThe analyst decision stays saved, but this analysis and the weekly report counts will no longer include it.")) return;
  try { await api("/api/history/" + it.id, { method: "DELETE" }); loaded.report = false; loadHistory(true); }
  catch (e) { const er = $("#hist-error"); er.textContent = e.message; show(er); }
}

async function openHistory(id) {
  try {
    const item = await api("/api/history/" + id);
    state.alertSent = item.alert; state.result = item.result; state.approvals = {}; state.feedback = {}; state.tab = "report";
    state.ingest = { ok: true, source_type: "history", alert: item.alert, warnings: [], needs_confirmation: false };
    try { (await api("/api/feedback/" + encodeURIComponent(item.alert_id))).forEach((f) => { state.feedback[f.claim_id] = f.decision; }); } catch (_) { /* optional */ }
    switchView("analyze");
    renderResults(); goStep(3);
    const note = h("div", { class: "notice from-history" },
      h("span", {}, `Opened from history. This analysis was run ${utcToLocal(item.submitted_at)}${item.username ? " by " + item.username : ""}, with the knowledge base as it was then.`), " ",
      h("button", { class: "btn small", type: "button", onclick: () => { showConfirm(); } }, "Analyze again with today's knowledge base"));
    $("#summary").prepend(note);
  } catch (e) { const er = $("#hist-error"); er.textContent = e.message; show(er); }
}

function initHistory() {
  const reload = () => loadHistory(true);
  $("#h-q").addEventListener("input", () => { clearTimeout(hist.timer); hist.timer = setTimeout(reload, 300); });
  ["#h-sev", "#h-days", "#h-mine"].forEach((s) => $(s).addEventListener("change", reload));
  $("#hist-more").addEventListener("click", () => loadHistory(false));
}

/* ================================================================ 04 weekly report */
function delta(d, goodWhenDown) {
  if (!d || d.change === 0) return h("span", { class: "delta flat" }, "no change");
  const up = d.change > 0, bad = goodWhenDown ? up : false;
  return h("span", { class: "delta " + (bad ? "bad" : "neutral") }, `${up ? "▲" : "▼"} ${Math.abs(d.change)}${d.percent != null ? ` (${d.percent > 0 ? "+" : ""}${d.percent}%)` : ""} vs last week`);
}

function kpi(label, value, extra) { return h("div", { class: "kpi" }, h("span", { class: "kpi-label" }, label), h("b", { class: "kpi-value" }, value), extra || null); }

function barChart(days) {
  const max = Math.max(1, ...days.map((d) => d.count));
  return h("div", { class: "bars", role: "img", "aria-label": "Alerts per day: " + days.map((d) => `${d.label} ${d.count}`).join(", ") },
    days.map((d) => h("div", { class: "bar-col", title: `${d.label} ${d.date}: ${d.count} alert(s), ${d.high_critical} high or critical` },
      h("span", { class: "bar-n" }, d.count || ""),
      h("div", { class: "bar-track" }, h("div", { class: "bar", style: `height:${Math.round((d.count / max) * 100)}%` }, d.high_critical ? h("div", { class: "bar-hi", style: `height:${Math.round((d.high_critical / d.count) * 100)}%` }) : null)),
      h("span", { class: "bar-l" }, d.label))));
}

function miniTable(headers, rows) {
  if (!rows.length) return h("p", { class: "muted" }, "None this week.");
  return h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, headers.map((x) => h("th", {}, x)))),
    h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c) => h("td", {}, c)))))));
}

function renderWeeklyReport(rep) {
  const t = rep.totals, c = rep.comparison, w = rep.week;
  const sevTotal = Object.values(rep.severity).reduce((a, b) => a + b, 0) || 1;
  $("#rep-sub").textContent = `${w.label} · weeks run Monday to Sunday (UTC)` + (w.partial ? " · still in progress" : "");
  const body = $("#rep-body");
  if (t.alerts === 0) {
    body.replaceChildren(h("div", { class: "empty" }, h("strong", {}, "No alerts were analysed this week."), h("p", { class: "muted" }, "Analysed alerts appear here automatically."),
      h("button", { class: "btn primary small", type: "button", onclick: () => switchView("analyze") }, "Analyze an alert")));
    return;
  }
  body.replaceChildren(
    h("div", { class: "kpis" },
      kpi("Alerts analysed", t.alerts, delta(c.alerts, false)),
      kpi("High or critical", t.high_critical, delta(c.high_critical, true)),
      kpi("Avg. verification", t.average_verification == null ? "–" : t.average_verification + "%", h("span", { class: "delta flat" }, `${t.analysts} analyst${t.analysts === 1 ? "" : "s"}`))),
    rep.insights.length ? h("div", { class: "notice insights" }, h("strong", {}, "Points to check"), h("ul", {}, rep.insights.map((i) => h("li", {}, i)))) : null,
    h("div", { class: "rep-grid" },
      h("div", {}, h("h3", {}, "Alerts per day"), barChart(rep.per_day), h("p", { class: "muted sm" }, "The darker part of a bar is high or critical alerts.")),
      h("div", {}, h("h3", {}, "By severity"),
        h("div", { class: "stack", role: "img", "aria-label": Object.entries(rep.severity).map(([k, n]) => `${k} ${n}`).join(", ") },
          Object.entries(rep.severity).filter(([, n]) => n).map(([k, n]) => h("span", { class: "seg " + sevClass(k), style: `flex:${n}`, title: `${k}: ${n}` }, n))),
        h("ul", { class: "legend" }, Object.entries(rep.severity).map(([k, n]) => h("li", {}, h("i", { class: "dot " + sevClass(k) }), `${k}: ${n} (${Math.round((n / sevTotal) * 100)}%)`))),
      )),
    h("div", { class: "rep-grid" },
      h("div", {}, h("h3", {}, "Top rules"), miniTable(["Rule", "Description", "Alerts"], rep.top_rules.map((r) => [r.rule_id, r.description.slice(0, 70), r.count]))),
      h("div", {}, h("h3", {}, "Top ATT&CK techniques"), miniTable(["Technique", "Alerts"], rep.top_techniques.map((x) => [h("a", { href: "https://attack.mitre.org/techniques/" + x.id.replace(".", "/"), target: "_blank", rel: "noopener noreferrer" }, x.id), x.count])))),
    h("div", { class: "rep-grid" },
      h("div", {}, h("h3", {}, "Most affected hosts"), miniTable(["Host", "Alerts"], rep.top_hosts.map((x) => [x.name, x.count]))),
      h("div", {}, h("h3", {}, "Most frequent source IPs"), miniTable(["Source IP", "Alerts"], rep.top_sources.map((x) => [x.ip, x.count])))),
    h("h3", {}, "High and critical alerts"),
    miniTable(["Time", "Severity", "Alert", "Host", ""], rep.notable.map((n) => [utcToLocal(n.time), h("span", { class: "badge " + sevClass(n.severity) }, n.severity),
      n.description.slice(0, 90), n.host || "–",
      h("button", { class: "btn small", type: "button", onclick: () => openHistory(n.history_id) }, "Open")])),
    h("p", { class: "muted sm" }, `Generated ${w.generated_at}. Finished weeks are also saved automatically as Markdown files in backend/data/reports.`));
}

async function loadReport(force) {
  const sel = $("#rep-week"), er = $("#rep-error"); show(er, false);
  try {
    if (!loaded.report || force) {
      const weeks = await api("/api/reports/weeks"), keep = sel.value;
      sel.replaceChildren(...weeks.map((wk) => h("option", { value: wk.start }, `${wk.label} · ${wk.alerts} alert${wk.alerts === 1 ? "" : "s"}`)));
      if (keep && weeks.some((wk) => wk.start === keep)) sel.value = keep;
      loaded.report = true;
    }
    const ws = sel.value;
    const rep = await api("/api/reports/weekly?week_start=" + encodeURIComponent(ws));
    $("#rep-md").href = "/api/reports/weekly.md?week_start=" + encodeURIComponent(ws);
    $("#rep-csv").href = "/api/reports/weekly.csv?week_start=" + encodeURIComponent(ws);
    renderWeeklyReport(rep);
  } catch (e) { if (!e.auth) { er.textContent = e.message; show(er); } }
}

function initReport() {
  $("#rep-week").addEventListener("change", () => loadReport());
  $("#rep-print").addEventListener("click", () => window.print());
}

/* ================================================================ 02 synchronized dataset */
const DS_STATE = {
  up_to_date: ["ok", "Up to date", "The search index matches the source files."],
  changes_pending: ["warn", "Changes waiting", "The sources or the index have changed since the last sync."],
  never_synced: ["bad", "Not built yet", "The knowledge base is empty."],
  untracked: ["warn", "Not tracked yet", "Built before synchronisation existed. One sync starts the tracking."],
  error: ["bad", "Problem", "The source files could not be checked."],
};
const FILE_STATE = { unchanged: "Unchanged", changed: "Changed", new: "New", removed: "Removed", unknown: "Not tracked yet" };
const SOURCE_LABEL = { mitre: "MITRE ATT&CK", nist: "NIST CSF 2.0", incident_response: "Incident response" };
let dsPoll = null;

function fmtBytes(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB"; }

function renderDatasetResult(r, dry) {
  const dismissKey = `${r.added_or_updated}-${r.failed}-${r.seconds}`;
  try { if (!dry && localStorage.getItem("serc-ds-dismissed") === dismissKey) return null; } catch (e) {}
  const bits = [`${r.to_add} to add`, `${r.to_update} to update`, `${r.unchanged} unchanged`, `${r.stale} stale`];
  if (!dry) { bits.splice(0, 3, `${r.added_or_updated} added or updated`, `${r.unchanged} unchanged`); bits.push(`${r.removed} removed`); if (r.failed) bits.push(`${r.failed} failed`); }
  const box = h("div", { class: "notice " + (r.failed ? "" : "ok") },
    h("button", { class: "btn", type: "button", title: "Dismiss", "aria-label": "Dismiss", style: "float:right;padding:2px 10px;line-height:1.2",
      onclick: () => { box.remove(); try { if (!dry) localStorage.setItem("serc-ds-dismissed", dismissKey); } catch (e) {} } }, "\u00d7"),
    h("strong", {}, dry ? "Preview (nothing was changed)" : "Sync finished"), h("div", {}, bits.join(" · ") + ` · ${r.seconds}s`),
    r.model_changed ? h("div", {}, "The embedding model changed, so every passage is re-embedded.") : null,
    ...(r.notes || []).map((n) => h("div", {}, n)),
    !dry && r.stale_left ? h("div", {}, `${r.stale_left} stale passage(s) were kept. Tick “Also remove stale passages” and sync again to delete them.`) : null);
  if (!dry) {   // a finished-sync message clears itself after a few seconds (previews stay until you act)
    setTimeout(() => { if (box.isConnected) { box.remove(); try { localStorage.setItem("serc-ds-dismissed", dismissKey); } catch (e) {} } }, 8000);
  }
  return box;
}

function renderDataset(st, extra) {
  const body = $("#ds-body");
  const [cls, title, sub] = DS_STATE[st.state] || ["warn", st.state, ""];
  const job = st.job || {};
  const running = job.state === "running";
  const prune = h("input", { type: "checkbox", id: "ds-prune", checked: !!(extra && extra.prune) });
  const syncBtn = h("button", { class: "btn primary", type: "button", disabled: !isAdmin() || running, onclick: () => startSync() }, running ? "Synchronizing…" : "Synchronize now");
  const previewBtn = h("button", { class: "btn", type: "button", disabled: !isAdmin() || running, onclick: () => previewSync() }, "Preview changes");
  const pct = job.total ? Math.round((job.done / job.total) * 100) : 0;
  const parts = [
    h("div", { class: "ds-status ds-" + cls }, h("span", { class: "ds-dot" }), h("div", {}, h("strong", {}, title), h("div", { class: "muted" }, sub))),
    st.issues && st.issues.length ? h("ul", { class: "notice-list" }, st.issues.map((i) => h("li", {}, i))) : null,
    h("div", { class: "kpis" },
      kpi("Passages in the index", st.stored.toLocaleString()),
      kpi("Recorded at last sync", st.recorded ? st.recorded.toLocaleString() : "–"),
      kpi("Last sync", st.last_sync || "never"),
      kpi("Scope", st.scope === "full" ? "Full ATT&CK" : "Quick set", h("span", { class: "delta flat" }, st.embedding_model || ""))),
    st.counts && Object.keys(st.counts).length ? h("p", { class: "muted" }, "Per source: " + Object.entries(st.counts).map(([k, n]) => `${SOURCE_LABEL[k] || k} ${n.toLocaleString()}`).join(" · ")) : null,
    running ? h("div", { class: "progress-wrap" }, h("div", { class: "progress-label" }, `${job.phase}${job.total ? ` (${job.done} of ${job.total})` : "…"}`),
      h("div", { class: "sync-meter" }, h("span", { style: `width:${job.total ? pct : 8}%` }))) : null,
    job.state === "failed" ? h("p", { class: "error" }, "The last synchronisation failed: " + job.error) : null,
    extra && extra.result ? renderDatasetResult(extra.result, extra.dry) : (job.state === "done" && job.result ? renderDatasetResult(job.result, false) : (st.last_result ? renderDatasetResult(st.last_result, false) : null)),
    h("div", { class: "ds-actions" }, previewBtn, syncBtn,
      h("label", { class: "switch" }, prune, h("span", {}, "Also remove stale passages")),
      isAdmin() ? null : h("span", { class: "muted sm" }, "Only an administrator can synchronize.")),
    h("p", { class: "muted sm" }, "Unchanged passages are never embedded again, so a sync after a small update is quick. Searches keep working while it runs."),
    h("h3", {}, "Source files"),
    h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["File", "Feeds", "Size", "Modified (UTC)", "Status"].map((x) => h("th", {}, x)))),
      h("tbody", {}, (st.files || []).map((f) => h("tr", {}, h("td", {}, f.name), h("td", {}, SOURCE_LABEL[f.source] || f.source), h("td", { class: "nowrap" }, fmtBytes(f.size)), h("td", { class: "nowrap" }, f.modified || "–"),
        h("td", {}, h("span", { class: "status " + (f.state === "unchanged" ? "st-ok" : f.state === "unknown" ? "st-review" : "st-warn") }, FILE_STATE[f.state] || f.state)))))))
  ];
  body.replaceChildren(...parts.filter(Boolean));
}

async function loadDataset(extra) {
  const er = $("#ds-error"); show(er, false);
  try {
    const st = await api("/api/dataset/status");
    renderDataset(st, extra);
    clearTimeout(dsPoll);
    if (st.job && st.job.state === "running") dsPoll = setTimeout(() => $("#view-dataset").classList.contains("hidden") ? null : loadDataset(extra), 1500);
    else if (st.job && st.job.state === "done" && extra && extra.refreshHealth) { extra.refreshHealth = false; refreshHealth(); }
  } catch (e) { if (!e.auth) { er.textContent = e.message; show(er); } }
}

async function refreshHealth() { try { state.health = await api("/api/health"); renderPills(); } catch (_) { /* pills are optional */ } }

async function startSync() {
  const er = $("#ds-error"); show(er, false);
  try { await postJSON("/api/dataset/sync", { prune: $("#ds-prune").checked }); loadDataset({ refreshHealth: true, prune: $("#ds-prune").checked }); }
  catch (e) { er.textContent = e.message; show(er); }
}

async function previewSync() {
  const er = $("#ds-error"); show(er, false);
  const btn = [...$$("#ds-body button")].find((b) => b.textContent === "Preview changes");
  if (btn) { btn.disabled = true; btn.textContent = "Reading the sources…"; }
  try { const r = await postJSON("/api/dataset/preview", {}); const st = await api("/api/dataset/status"); renderDataset(st, { result: r, dry: true, prune: $("#ds-prune") && $("#ds-prune").checked }); }
  catch (e) { er.textContent = e.message; show(er); if (btn) { btn.disabled = false; btn.textContent = "Preview changes"; } }
}

/* ================================================================ start */
document.addEventListener("DOMContentLoaded", () => {
  $$("#viewnav .vtab").forEach((b) => b.addEventListener("click", () => switchView(b.dataset.view)));
  initInputs(); initHistory(); initReport();
  // after a new analysis the history and the weekly counts are out of date
  const analyzeBtn = $("#btn-analyze");
  if (analyzeBtn) analyzeBtn.addEventListener("click", () => { loaded.report = false; });
});
