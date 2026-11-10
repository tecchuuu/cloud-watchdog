// app.js — the dashboard: findings table, Fix / Delete / Ignore, Report tab.
// Every piece of data comes from the API (config.js -> apiUrl), with the
// login token from auth.js.

const $ = (id) => document.getElementById(id);

const STALE_HOURS = 26; // daily scan + 2 h slack; older than this = something's wrong
const SEVERITY_ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2 };

// Plain-English tooltips for the CIS Benchmark labels on security findings
const CIS_TIPS = {
  "CIS 5.2": "CIS AWS Foundations 5.2: no security group should let the whole internet (0.0.0.0/0) reach admin ports like SSH (22) or RDP (3389).",
  "CIS 5.3": "CIS AWS Foundations 5.3: same rule for IPv6: admin ports must not be open to ::/0.",
  "CIS 2.1.4": "CIS AWS Foundations 2.1.4: S3 buckets should have Block Public Access turned on so files can't leak to the internet.",
};

let findings = [];   // what GET /findings returned last
let lastReport = null;

// ------------------------------------------------------------------ helpers

// Text from AWS (resource names, tags) is put on the page as text, never as
// HTML, so a resource named "<script>..." can't run code in the dashboard.
function esc(value) {
  const div = document.createElement("div");
  div.textContent = value ?? "";
  return div.innerHTML;
}

function money(usd) {
  return usd ? `$${Number(usd).toFixed(2)}` : "–";
}

function timeAgo(iso) {
  if (!iso) return "never";
  const minutes = Math.round((Date.now() - new Date(iso)) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.round(hours / 24)} days ago`;
}

function localTime(iso) {
  return iso ? new Date(iso).toLocaleString() : "";
}

function toast(message, isError = false) {
  const t = $("toast");
  t.textContent = message;
  t.className = isError ? "toast error" : "toast";
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), 5000);
}

// ---------------------------------------------------------------- the API

// While any request is running, a thin moving bar shows at the top of the page,
// so the user always knows the app is working (HCI: visibility of system status).
let pending = 0;
function setLoading(delta) {
  pending += delta;
  $("loading-bar").hidden = pending === 0;
}

// Call one route, e.g. api("POST", "/fix", {finding_ids: [...]}).
async function api(method, path, body) {
  setLoading(+1);
  try {
    return await apiCall(method, path, body);
  } finally {
    setLoading(-1);
  }
}

// Sends the ID token; on 401 tries one refresh, then sends you to the login page.
async function apiCall(method, path, body) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const token = await getToken();
    if (!token) return login();
    const resp = await fetch(CONFIG.apiUrl + path, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (resp.status === 401 && attempt === 0 && (await refresh())) continue;
    if (resp.status === 401) return login();
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || data.message || `HTTP ${resp.status}`);
    return data;
  }
}

// ------------------------------------------------------------- findings view

async function loadFindings() {
  const [f, r] = await Promise.all([api("GET", "/findings"), api("GET", "/report")]);
  findings = f.findings.sort((a, b) =>
    (a.status === "IGNORED") - (b.status === "IGNORED") ||           // ignored at the bottom
    SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||       // then by risk
    (b.est_monthly_usd || 0) - (a.est_monthly_usd || 0));            // then by cost
  lastReport = r;
  renderFindings();
  renderHeader();
}

function renderHeader() {
  const s = lastReport.summary;
  const badge = $("grade-badge");
  badge.textContent = s.grade || "–";
  badge.className = `grade-badge grade-${s.grade || "none"}`;

  $("s-score").textContent = s.score != null ? `${s.score} / 100` : "";

  const lastScan = $("last-scan");
  lastScan.textContent = timeAgo(lastReport.last_scan);
  lastScan.title = localTime(lastReport.last_scan);
  const stale = !lastReport.last_scan ||
    Date.now() - new Date(lastReport.last_scan) > STALE_HOURS * 3600 * 1000;
  lastScan.className = stale ? "stale" : "";

  // Summary box: the same numbers the Report tab shows
  $("s-high").textContent = s.counts.HIGH;
  $("s-medium").textContent = s.counts.MEDIUM;
  $("s-low").textContent = s.counts.LOW;
  $("s-wasted").textContent = `$${Number(s.wasted_usd || 0).toFixed(2)}`;
  $("s-saved").textContent = `$${Number(s.saved_usd || 0).toFixed(2)}`;
}

function renderFindings() {
  $("findings-body").innerHTML = findings.map((f) => {
    const ignored = f.status === "IGNORED";
    const cis = f.cis
      ? ` <span class="chip" data-tip="${esc(CIS_TIPS[f.cis] || f.cis)}">${esc(f.cis)}</span>` : "";
    const note = ignored ? `<div class="muted small">Ignored: ${esc(f.ignore_reason)}</div>` : "";
    const actions = ignored ? "" : `
        <button data-act="FIX" data-id="${esc(f.finding_id)}">Fix</button>
        <button data-act="DELETE" data-id="${esc(f.finding_id)}" class="danger">Delete</button>
        <button data-act="IGNORE" data-id="${esc(f.finding_id)}">Ignore</button>`;
    const category = f.category === "cost" ? "Cost" : "Security";
    return `
      <tr class="row-${esc(f.severity)} ${ignored ? "ignored" : ""}">
        <td><input type="checkbox" class="pick" value="${esc(f.finding_id)}" ${ignored ? "disabled" : ""}></td>
        <td><span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span></td>
        <td><span class="status status-${esc(f.status)}">${esc(f.status)}</span></td>
        <td>${esc(f.resource_name)}<div class="muted small">${esc(f.region)}</div></td>
        <td><span class="cat">${category}</span> ${esc(f.detail)}${cis}${note}</td>
        <td class="num">${money(f.est_monthly_usd)}</td>
        <td class="row-actions">${actions}</td>
      </tr>`;
  }).join("");
  const active = findings.filter((f) => f.status !== "IGNORED").length;
  $("findings-count").textContent = active ? `(${active})` : "";
  $("findings-empty").hidden = active > 0;
  $("select-all").checked = false;
  updateBulkButtons();
}

function selectedIds() {
  return [...document.querySelectorAll(".pick:checked")].map((c) => c.value);
}

function updateBulkButtons() {
  const n = selectedIds().length;
  $("fix-selected").disabled = n === 0;
  $("delete-selected").disabled = n === 0;
  $("fix-all").disabled = !findings.some((f) => f.status !== "IGNORED");
}

// ------------------------------------------------------------------- popup

// Show the popup; resolves true if Confirm was pressed.
function popup(title, html, { okText = "Confirm", danger = false, showCancel = true } = {}) {
  $("popup-title").textContent = title;
  $("popup-body").innerHTML = html;
  $("popup-ok").textContent = okText;
  $("popup-ok").className = danger ? "danger" : "primary";
  $("popup-cancel").hidden = !showCancel;
  $("popup-buttons").hidden = false;
  if (!$("popup").open) $("popup").showModal();
  return new Promise((resolve) => {
    $("popup-ok").onclick = () => { $("popup").close(); resolve(true); };
    $("popup-cancel").onclick = () => { $("popup").close(); resolve(false); };
    $("popup").oncancel = () => resolve(false); // Esc key
  });
}

// Popup with a spinner and no buttons, shown while a request runs.
// The next popup() or closeWorking() replaces it.
function working(title) {
  $("popup-title").textContent = title;
  $("popup-body").innerHTML = `<p class="muted"><span class="spinner"></span> Working on it…</p>`;
  $("popup-buttons").hidden = true;
  if (!$("popup").open) $("popup").showModal();
}

function closeWorking() {
  if ($("popup").open && $("popup-buttons").hidden) $("popup").close();
}

// Button shows a spinner + text while busy. With countSeconds, the text
// counts up ("Scanning… 12s") so a long wait doesn't look frozen.
function busy(button, text, countSeconds = false) {
  const old = button.textContent;
  const started = Date.now();
  button.disabled = true;
  button.classList.add("is-busy");
  const show = () => {
    const secs = Math.round((Date.now() - started) / 1000);
    button.textContent = countSeconds && secs > 0 ? `${text} ${secs}s` : text;
  };
  show();
  const timer = countSeconds ? setInterval(show, 1000) : null;
  return () => {
    clearInterval(timer);
    button.disabled = false;
    button.classList.remove("is-busy");
    button.textContent = old;
  };
}

// ----------------------------------------------------------------- actions

// Fix or Delete: preview first (changes nothing), confirm, then do it.
async function fixOrDelete(action, ids) {
  if (!ids.length) return;
  const verb = action === "FIX" ? "Fix" : "Delete";
  working(`${verb}: checking what will change…`);
  let preview;
  try {
    ({ preview } = await api("POST", "/preview", { action, finding_ids: ids }));
  } finally {
    closeWorking();
  }
  const rows = preview.map((p) =>
    `<li><b>${esc(p.resource_name || p.finding_id)}</b> <span class="muted">${esc(p.region || "")}</span><br>${esc(p.will)}</li>`
  ).join("");
  const warning = action === "DELETE"
    ? `<p class="warn">Delete can't be undone. The resource is gone for good.</p>` : "";
  const ok = await popup(
    `${action === "FIX" ? "Fix" : "Delete"} ${ids.length} finding${ids.length > 1 ? "s" : ""}?`,
    `${warning}<ul class="preview">${rows}</ul>`,
    { okText: action === "FIX" ? "Fix" : "Delete", danger: action === "DELETE" });
  if (!ok) return;

  working(`${action === "FIX" ? "Fixing" : "Deleting"} ${ids.length} finding${ids.length > 1 ? "s" : ""}…`);
  try {
    const { results } = await api("POST", action === "FIX" ? "/fix" : "/delete", { finding_ids: ids });
    await showResults(results);
  } finally {
    closeWorking();
  }
}

async function ignore(id) {
  const f = findings.find((x) => x.finding_id === id);
  const ok = await popup(`Ignore ${f.resource_name}?`, `
    <p>Watchdog tags it <code>watchdog-ignore=true</code> and future scans skip it.
       The reason goes into the audit log.</p>
    <textarea id="ignore-reason" rows="3" placeholder="Why is this OK? (required)"></textarea>`,
    { okText: "Ignore" });
  if (!ok) return;
  const reason = $("ignore-reason").value.trim();
  if (!reason) return toast("Ignore needs a reason", true);
  working(`Ignoring ${f.resource_name}…`);
  try {
    const { results } = await api("POST", "/ignore", { finding_id: id, reason });
    await showResults(results);
  } finally {
    closeWorking();
  }
}

async function showResults(results) {
  const rows = results.map((r) => {
    const name = findings.find((f) => f.finding_id === r.finding_id)?.resource_name || r.finding_id;
    return `<li><span class="result result-${esc(r.result)}">${esc(r.result)}</span>
            <b>${esc(name)}</b> <span class="muted">log #${esc(r.log_seq)}</span><br>
            ${esc(r.done || r.error || (r.result === "ALREADY_FIXED" ? "Nothing to do: already fixed or gone" : ""))}</li>`;
  }).join("");
  await popup("Done", `<ul class="preview">${rows}</ul>`, { okText: "OK", showCancel: false });
  await loadFindings();
}

async function scanNow() {
  const done = busy($("scan-now"), "Scanning…", true); // ~10-25 s, so count the seconds
  try {
    const s = await api("POST", "/scan");
    toast(`Scan done: grade ${s.grade}, ${s.new} new, ${s.open} still open`);
    await loadFindings();
    if (!$("view-report").hidden) await loadReport();
  } catch (e) {
    // API Gateway gives up after 30 s; the scan itself keeps running in Lambda
    toast(`Scan: ${e.message}. If it timed out, refresh in a minute.`, true);
  } finally {
    done();
  }
}

// --------------------------------------------------------------- report view

async function loadReport() {
  if (!lastReport) {
    $("log-body").innerHTML = `<tr><td colspan="8" class="loading-row"><span class="spinner"></span> Loading report…</td></tr>`;
  }
  const r = await api("GET", "/report");
  lastReport = r;
  const s = r.summary;

  $("r-grade").textContent = s.grade || "–";
  $("r-grade").className = `card-big grade-text-${s.grade || "none"}`;
  $("r-score").textContent = s.score != null ? `score ${s.score} / 100` : "";
  $("r-open").textContent = s.new + s.open;
  $("r-counts").textContent = `${s.counts.HIGH} high · ${s.counts.MEDIUM} medium · ${s.counts.LOW} low`;
  $("r-wasted").textContent = money(s.wasted_usd) === "–" ? "$0.00" : money(s.wasted_usd);
  $("r-saved").textContent = money(s.saved_usd) === "–" ? "$0.00" : money(s.saved_usd);
  $("r-fixed").textContent = `per month, ${s.fixed_total} fixed`;

  // History: one bar per scan, height = score
  $("history-chart").innerHTML = r.history.length ? r.history.map((h) => {
    const total = h.counts.HIGH + h.counts.MEDIUM + h.counts.LOW;
    return `<div class="bar-wrap" data-tip="${esc(localTime(h.scanned_at))}: grade ${esc(h.grade)} (${h.score}), ${total} open">
              <div class="bar grade-bg-${esc(h.grade)}" style="height:${Math.max(h.score, 3)}%"></div>
              <div class="bar-label">${esc(h.grade)}</div>
            </div>`;
  }).join("") : `<p class="muted">No scans yet.</p>`;

  $("log-body").innerHTML = r.audit_log.map((e) => `
    <tr>
      <td>${esc(e.seq)}</td>
      <td title="${esc(e.ts)}">${esc(localTime(e.ts))}</td>
      <td><b>${esc(e.user)}</b></td>
      <td>${esc(e.action)}</td>
      <td><span class="result result-${esc(e.result)}">${esc(e.result)}</span></td>
      <td class="small">${esc(e.finding_id)}</td>
      <td class="small">${esc(e.reason || e.error || "")}</td>
      <td class="mono small" title="${esc(e.hash)}">${esc((e.hash || "").slice(0, 10))}…</td>
    </tr>`).join("") || `<tr><td colspan="8" class="muted">Nothing done yet.</td></tr>`;

  $("ignored-body").innerHTML = r.ignored.map((f) => `
    <tr><td>${esc(f.resource_name)}<div class="muted small">${esc(f.region)}</div></td>
        <td>${esc(f.detail)}</td><td>${esc(f.ignore_reason)}</td></tr>`).join("")
    || `<tr><td colspan="3" class="muted">Nothing ignored.</td></tr>`;
}

async function verifyLog() {
  const done = busy($("verify-log"), "Checking…");
  try {
    const v = await api("GET", "/verify-log");
    $("verify-result").innerHTML = v.ok
      ? `<span class="ok">✔ Intact: all ${v.entries} entries check out</span>`
      : `<span class="bad">✘ Broken at entry #${esc(v.broken_at)}: it was changed or removed</span>`;
  } finally {
    done();
  }
}

// ------------------------------------------------------------- CSV download

function downloadCsv(filename, rows, columns) {
  const cell = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const csv = [columns.join(","), ...rows.map((r) => columns.map((c) => cell(r[c])).join(","))].join("\n");
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

async function csvFindings() {
  const { findings: all } = await api("GET", "/findings?all=1"); // includes FIXED
  downloadCsv("watchdog-findings.csv", all, ["finding_id", "check", "category", "severity", "status",
    "region", "resource_id", "resource_name", "detail", "est_monthly_usd", "cis",
    "first_seen", "last_seen", "fixed_at", "ignore_reason"]);
}

function csvLog() {
  downloadCsv("watchdog-audit-log.csv", [...lastReport.audit_log].reverse(),
    ["seq", "ts", "user", "action", "finding_id", "result", "reason", "error", "prev_hash", "hash"]);
}

// ------------------------------------------------------------------- wiring

function showView(name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === name));
  $("view-findings").hidden = name !== "findings";
  $("view-report").hidden = name !== "report";
  (name === "report" ? loadReport() : loadFindings()).catch((e) => toast(e.message, true));
}

// Run fn, show any error as a red message instead of failing silently
const safe = (fn) => (...args) => fn(...args).catch((e) => toast(e.message, true));

function wireUp() {
  document.querySelectorAll(".tab").forEach((t) => (t.onclick = () => showView(t.dataset.view)));
  $("logout").onclick = logout;
  $("scan-now").onclick = scanNow;
  $("fix-selected").onclick = safe(() => fixOrDelete("FIX", selectedIds()));
  $("delete-selected").onclick = safe(() => fixOrDelete("DELETE", selectedIds()));
  $("fix-all").onclick = safe(() => fixOrDelete("FIX",
    findings.filter((f) => f.status !== "IGNORED").map((f) => f.finding_id)));
  $("verify-log").onclick = safe(verifyLog);
  $("csv-findings").onclick = safe(csvFindings);
  $("csv-log").onclick = csvLog;

  $("select-all").onchange = (e) => {
    document.querySelectorAll(".pick:not(:disabled)").forEach((c) => (c.checked = e.target.checked));
    updateBulkButtons();
  };
  $("findings-body").onchange = updateBulkButtons;
  $("findings-body").onclick = safe(async (e) => {   // Fix / Delete / Ignore on one row
    const b = e.target.closest("button[data-act]");
    if (!b) return;
    if (b.dataset.act === "IGNORE") await ignore(b.dataset.id);
    else await fixOrDelete(b.dataset.act, [b.dataset.id]);
  });

  setInterval(() => lastReport && renderHeader(), 60_000); // keep "X min ago" fresh
}

// ------------------------------------------------------------------- theme

// The ☾/☀ button flips data-theme on <html>; style.css swaps the colour values.
// The choice is remembered in this browser (localStorage).
function setupThemeToggle() {
  const button = $("theme-toggle");
  const show = () => {
    const dark = document.documentElement.dataset.theme === "dark";
    button.textContent = dark ? "☀" : "☾";
    button.title = dark ? "Switch to light" : "Switch to dark";
  };
  button.onclick = () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("theme", next); } catch { /* private window: just don't remember */ }
    show();
  };
  show();
}

// ------------------------------------------------------------------- start

setupThemeToggle();

(async function start() {
  try {
    await handleRedirect();               // just came back from Cognito?
    if (!(await getToken())) return login();
    $("username").textContent = currentUser();
    wireUp();
    await loadFindings();
  } catch (e) {
    toast(e.message, true);
  }
})();
