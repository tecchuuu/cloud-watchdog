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

// What each button does, shown when the mouse rests on it
const ACTION_HINTS = {
  FIX: "Fix: remove the risk but keep the resource. You see a preview first.",
  DELETE: "Delete: remove the resource for good. You are asked to confirm.",
  IGNORE: "Ignore: mark this as OK, with a reason. Future scans skip it.",
};

let findings = [];   // what GET /findings returned last
let lastReport = null;

// ------------------------------------------------------------------ helpers

// Text from AWS (resource names, tags) is always escaped before it goes on
// the page, so a resource named "<script>..." can't run code in the dashboard.
// Quotes are escaped too, so the text is also safe inside title="..." etc.
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function money(usd) {
  return usd ? `$${Number(usd).toFixed(2)}` : "–";
}

// "5 min", "3 h", "4 days": how long since a time
function duration(iso) {
  const minutes = Math.round((Date.now() - new Date(iso)) / 60000);
  if (minutes < 1) return "under a minute";
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h`;
  return `${Math.round(hours / 24)} days`;
}

function timeAgo(iso) {
  if (!iso) return "never";
  const d = duration(iso);
  return d === "under a minute" ? "just now" : `${d} ago`;
}

function localTime(iso) {
  return iso ? new Date(iso).toLocaleString() : "";
}

// "sg-0abc · us-east-1" as safe HTML. The AWS ID tells two same-named resources
// apart, and it's what you search for in the AWS console. (A bucket's ID is its
// name, so it isn't repeated.) The ID never breaks in the middle of a line.
function idAndRegion(f) {
  if (!f) return "";
  const id = f.resource_id && f.resource_id !== f.resource_name
    ? `<span class="nowrap">${esc(f.resource_id)}</span> · ` : "";
  return id + esc(f.region);
}

// Browser errors like "Failed to fetch" mean nothing to most people: say what to check.
function friendly(error) {
  if (error instanceof TypeError && /fetch|network|load failed/i.test(error.message)) {
    return "Can't reach the Watchdog API. Check your internet connection. " +
           "On a new install, check the CORS origin in API Gateway (README step 9).";
  }
  // API Gateway's own words when it can't run the Lambda. Seen when the Learner Lab session is off.
  if (/internal server error/i.test(error.message)) {
    return "The Watchdog API could not run. In an AWS Academy Learner Lab this happens " +
           "when the lab session is not started: start the lab, then try again.";
  }
  return error.message;
}

// Message at the bottom of the page. Good news goes away by itself;
// an error stays until you close it, so it can't be missed.
function toast(message, isError = false) {
  const t = $("toast");
  t.textContent = message;
  t.className = isError ? "toast error" : "toast";
  t.setAttribute("role", isError ? "alert" : "status"); // read out by screen readers
  if (isError) {
    const close = document.createElement("button");
    close.className = "toast-close";
    close.textContent = "×";
    close.setAttribute("aria-label", "Close message");
    close.onclick = () => (t.hidden = true);
    t.append(close);
  }
  t.hidden = false;
  clearTimeout(toast.timer);
  if (!isError) toast.timer = setTimeout(() => (t.hidden = true), 5000);
}

// A failed load must not leave "Loading…" on screen forever: say what went
// wrong, in the table itself, with a button to try again.
function showLoadError(tbodyId, columns, what, error, retry) {
  const body = $(tbodyId);
  body.innerHTML = `
    <tr><td colspan="${columns}" class="load-error">
      <b>Couldn't load the ${what}.</b>
      <div>${esc(friendly(error))}</div>
      <button class="retry">Try again</button>
    </td></tr>`;
  body.querySelector(".retry").onclick = () => {
    body.innerHTML = `<tr><td colspan="${columns}" class="loading-row"><span class="spinner"></span> Loading…</td></tr>`;
    retry();
  };
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
  let f, r;
  try {
    [f, r] = await Promise.all([api("GET", "/findings"), api("GET", "/report")]);
  } catch (e) {
    findings = [];
    showLoadError("findings-body", 7, "findings", e, loadFindings);
    $("findings-count").textContent = "";
    $("findings-empty").hidden = true;
    updateBulkButtons();
    return;
  }
  if (!f || !r) return; // on the way to the login page

  findings = f.findings.sort((a, b) =>
    (a.status === "IGNORED") - (b.status === "IGNORED") ||           // ignored at the bottom
    SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||       // then by risk
    (b.est_monthly_usd || 0) - (a.est_monthly_usd || 0));            // then by cost
  lastReport = r;
  renderFindings();
  renderSummary();
}

// The summary box beside the table
function renderSummary() {
  const s = lastReport.summary;
  const letter = $("grade-letter");
  letter.textContent = s.grade || "–";
  letter.className = `grade-letter grade-text-${s.grade || "none"}`;

  $("s-score").textContent = s.score != null ? `${s.score} / 100` : "";
  $("s-meter").style.width = `${s.score ?? 0}%`;
  $("s-meter").className = `meter-fill grade-bg-${s.grade || "none"}`;

  // Last scan: a warning sign and a sentence when it's too old, not only red text
  const never = !lastReport.last_scan;
  const stale = never || Date.now() - new Date(lastReport.last_scan) > STALE_HOURS * 3600 * 1000;
  const lastScan = $("last-scan");
  lastScan.textContent = (stale && !never ? "⚠ " : "") + timeAgo(lastReport.last_scan);
  lastScan.title = localTime(lastReport.last_scan);
  lastScan.className = stale ? "stale" : "";
  $("stale-note").hidden = !stale;
  $("stale-note").textContent = never
    ? "No scan yet. Press Scan now."
    : `No scan for over ${STALE_HOURS} hours. The daily scan may be failing: press Scan now.`;

  // The same numbers the Report tab shows
  $("s-high").textContent = s.counts.HIGH;
  $("s-medium").textContent = s.counts.MEDIUM;
  $("s-low").textContent = s.counts.LOW;
  $("s-wasted").textContent = `$${Number(s.wasted_usd || 0).toFixed(2)}`;
  $("s-saved").textContent = `$${Number(s.saved_usd || 0).toFixed(2)}`;
}

function renderFindings() {
  $("findings-body").innerHTML = findings.map((f) => {
    const ignored = f.status === "IGNORED";
    const category = f.category === "cost" ? "Cost" : "Security";
    // tabindex makes the CIS label reachable with the Tab key and a tap, not only a mouse
    const cis = f.cis
      ? ` <span class="chip" tabindex="0" role="note" aria-label="${esc(CIS_TIPS[f.cis] || f.cis)}"
                data-tip="${esc(CIS_TIPS[f.cis] || f.cis)}">${esc(f.cis)}</span>` : "";
    const note = ignored ? `<div class="small">Ignored: ${esc(f.ignore_reason)}</div>` : "";
    // How long it has been a problem: old ones first is a fair way to pick what to do
    const age = !ignored && f.first_seen
      ? `<div class="muted small" title="First seen ${esc(localTime(f.first_seen))}">for ${duration(f.first_seen)}</div>` : "";
    const actions = ignored ? "" : ["FIX", "DELETE", "IGNORE"].map((act) => `
        <button data-act="${act}" data-id="${esc(f.finding_id)}" title="${ACTION_HINTS[act]}"
                ${act === "DELETE" ? 'class="danger"' : ""}>${act[0] + act.slice(1).toLowerCase()}</button>`).join("");
    return `
      <tr class="row-${esc(f.severity)} ${ignored ? "ignored" : ""}">
        <td><input type="checkbox" class="pick" value="${esc(f.finding_id)}"
                   aria-label="Select ${esc(f.resource_name)}" ${ignored ? "disabled" : ""}></td>
        <td><span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span></td>
        <td><span class="status status-${esc(f.status)}">${esc(f.status)}</span>${age}</td>
        <td>${esc(f.resource_name)}<div class="muted small">${idAndRegion(f)}</div></td>
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
  markScrollable();
}

function selectedIds() {
  return [...document.querySelectorAll(".pick:checked")].map((c) => c.value);
}

// The bulk buttons say how many rows they will act on
function updateBulkButtons() {
  const n = selectedIds().length;
  $("fix-selected").disabled = n === 0;
  $("delete-selected").disabled = n === 0;
  $("fix-selected").textContent = n ? `Fix selected (${n})` : "Fix selected";
  $("delete-selected").textContent = n ? `Delete selected (${n})` : "Delete selected";
  $("fix-all").disabled = !findings.some((f) => f.status !== "IGNORED");
}

// On a narrow screen the table scrolls sideways inside its card, with the action
// buttons pinned to the right. A soft shadow beside them shows there is more underneath.
function markScrollable() {
  const box = document.querySelector(".table-scroll");
  box.classList.toggle("can-scroll", box.scrollWidth > box.clientWidth);
}

// ------------------------------------------------------------------- popup

// Show the popup; resolves true if the OK button was pressed.
// Focus starts on Cancel, so pressing Enter by accident never confirms.
function popup(title, html, { okText = "Confirm", danger = false, showCancel = true } = {}) {
  $("popup-title").textContent = title;
  $("popup-body").innerHTML = html;
  $("popup-ok").textContent = okText;
  $("popup-ok").className = danger ? "danger" : "primary";
  $("popup-ok").disabled = false;
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

// One line in a popup list: name, ID and region, then what happens / happened
function popupLine(findingId, fallbackName, badge, text) {
  const f = findings.find((x) => x.finding_id === findingId);
  return `<li>${badge}<b>${esc(f ? f.resource_name : fallbackName || findingId)}</b>
          <span class="muted small">${idAndRegion(f)}</span><br>${esc(text)}</li>`;
}

// Fix or Delete: preview first (changes nothing), confirm, then do it.
async function fixOrDelete(action, ids) {
  if (!ids.length) return;
  const verb = action === "FIX" ? "Fix" : "Delete";
  const many = `${ids.length} finding${ids.length > 1 ? "s" : ""}`;

  working(`${verb}: checking what will change…`);
  let preview;
  try {
    ({ preview } = await api("POST", "/preview", { action, finding_ids: ids }));
  } finally {
    closeWorking();
  }
  const rows = preview.map((p) => popupLine(p.finding_id, p.resource_name, "", p.will)).join("");
  const warning = action === "DELETE"
    ? `<p class="warn">Delete can't be undone. The resource is gone for good.</p>` : "";
  const ok = await popup(`${verb} ${many}?`, `${warning}<ul class="preview">${rows}</ul>`,
    { okText: verb, danger: action === "DELETE" });
  if (!ok) return;

  working(`${action === "FIX" ? "Fixing" : "Deleting"} ${many}…`);
  try {
    const { results } = await api("POST", action === "FIX" ? "/fix" : "/delete", { finding_ids: ids });
    await showResults(results);
  } finally {
    closeWorking();
  }
}

async function ignore(id) {
  const f = findings.find((x) => x.finding_id === id);
  const answer = popup(`Ignore ${f.resource_name}?`, `
    <p>Watchdog tags it <code>watchdog-ignore=true</code> and future scans skip it.
       The reason goes into the audit log.</p>
    <label for="ignore-reason">Why is this OK? (required)</label>
    <textarea id="ignore-reason" rows="3" maxlength="300"></textarea>`,
    { okText: "Ignore" });

  // The Ignore button stays off until a reason is typed, so the popup
  // can't be sent empty and thrown away.
  const reasonBox = $("ignore-reason");
  $("popup-ok").disabled = true;
  reasonBox.oninput = () => ($("popup-ok").disabled = !reasonBox.value.trim());
  reasonBox.focus();
  if (!(await answer)) return;

  const reason = reasonBox.value.trim();
  working(`Ignoring ${f.resource_name}…`);
  try {
    const { results } = await api("POST", "/ignore", { finding_id: id, reason });
    await showResults(results);
  } finally {
    closeWorking();
  }
}

// The title says what really happened ("3 done, 1 failed"), and failures come first.
async function showResults(results) {
  const count = (result) => results.filter((r) => r.result === result).length;
  const title = [
    count("OK") && `${count("OK")} done`,
    count("ALREADY_FIXED") && `${count("ALREADY_FIXED")} already fixed`,
    count("FAILED") && `${count("FAILED")} failed`,
  ].filter(Boolean).join(", ");

  const order = { FAILED: 0, OK: 1, ALREADY_FIXED: 2 };
  const rows = [...results].sort((a, b) => order[a.result] - order[b.result]).map((r) => {
    const badge = `<span class="result result-${esc(r.result)}">${esc(r.result.replace("_", " "))}</span> `;
    const text = r.done || r.error || (r.result === "ALREADY_FIXED" ? "Nothing to do: already fixed or gone" : "");
    return popupLine(r.finding_id, null, badge, `${text} (log #${r.log_seq})`);
  }).join("");
  await popup(title || "Done", `<ul class="preview">${rows}</ul>`, { okText: "OK", showCancel: false });
  await loadFindings();
}

async function scanNow() {
  const done = busy($("scan-now"), "Scanning…", true); // ~10-25 s, so count the seconds
  try {
    const s = await api("POST", "/scan");
    if (!s) return;
    toast(`Scan done: grade ${s.grade}, ${s.new} new, ${s.open} still open`);
    await loadFindings();
    if (!$("view-report").hidden) await loadReport();
  } catch (e) {
    // API Gateway gives up after 30 s; the scan itself keeps running in Lambda
    toast(`Scan problem: ${friendly(e)} If it only timed out, it is still running: refresh in a minute.`, true);
  } finally {
    done();
  }
}

// --------------------------------------------------------------- report view

async function loadReport() {
  if (!lastReport) {
    $("log-body").innerHTML = `<tr><td colspan="8" class="loading-row"><span class="spinner"></span> Loading report…</td></tr>`;
  }
  let r;
  try {
    r = await api("GET", "/report");
  } catch (e) {
    return showLoadError("log-body", 8, "report", e, loadReport);
  }
  if (!r) return; // on the way to the login page
  lastReport = r;
  const s = r.summary;

  $("r-grade").textContent = s.grade || "–";
  $("r-grade").className = `card-big grade-text-${s.grade || "none"}`;
  $("r-score").textContent = s.score != null ? `score ${s.score} / 100` : "";
  $("r-open").textContent = s.new + s.open;
  $("r-counts").textContent = `${s.counts.HIGH} high · ${s.counts.MEDIUM} medium · ${s.counts.LOW} low`;
  $("r-wasted").textContent = `$${Number(s.wasted_usd || 0).toFixed(2)}`;
  $("r-saved").textContent = `$${Number(s.saved_usd || 0).toFixed(2)}`;
  $("r-fixed").textContent = `per month, ${s.fixed_total} fixed`;

  // History: one bar per scan, height = score
  $("history-chart").innerHTML = r.history.length ? r.history.map((h) => {
    const total = h.counts.HIGH + h.counts.MEDIUM + h.counts.LOW;
    const tip = `${localTime(h.scanned_at)}: grade ${h.grade} (${h.score}), ${total} open`;
    return `<div class="bar-wrap" role="img" aria-label="${esc(tip)}" data-tip="${esc(tip)}">
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
      <td><span class="result result-${esc(e.result)}">${esc(String(e.result).replace("_", " "))}</span></td>
      <td class="small">${esc(e.finding_id)}</td>
      <td class="small">${esc(e.reason || e.error || "")}</td>
      <td class="mono small" title="${esc(e.hash)}">${esc((e.hash || "").slice(0, 10))}…</td>
    </tr>`).join("") || `<tr><td colspan="8" class="muted">Nothing done yet.</td></tr>`;

  $("ignored-body").innerHTML = r.ignored.map((f) => `
    <tr><td>${esc(f.resource_name)}<div class="muted small">${idAndRegion(f)}</div></td>
        <td>${esc(f.detail)}</td><td>${esc(f.ignore_reason)}</td></tr>`).join("")
    || `<tr><td colspan="3" class="muted">Nothing ignored.</td></tr>`;
}

async function verifyLog() {
  const done = busy($("verify-log"), "Checking…");
  try {
    const v = await api("GET", "/verify-log");
    if (!v) return;
    $("verify-result").innerHTML = v.ok
      ? `<span class="ok">✔ Intact: all ${esc(v.entries)} entries check out</span>`
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

async function csvLog() {
  if (!lastReport) return;
  downloadCsv("watchdog-audit-log.csv", [...lastReport.audit_log].reverse(),
    ["seq", "ts", "user", "action", "finding_id", "result", "reason", "error", "prev_hash", "hash"]);
}

// ------------------------------------------------------------------- wiring

function showView(name) {
  document.querySelectorAll(".tab").forEach((t) => {
    const active = t.dataset.view === name;
    t.classList.toggle("active", active);
    if (active) t.setAttribute("aria-current", "page"); else t.removeAttribute("aria-current");
  });
  $("view-findings").hidden = name !== "findings";
  $("view-report").hidden = name !== "report";
  (name === "report" ? loadReport() : loadFindings()).catch((e) => toast(friendly(e), true));
}

// Run fn; if it fails, show the reason as a red message instead of failing silently
const safe = (fn) => (...args) => fn(...args).catch((e) => toast(friendly(e), true));

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
  $("csv-log").onclick = safe(csvLog);

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

  window.addEventListener("resize", markScrollable);
  setInterval(() => lastReport && renderSummary(), 60_000); // keep "X min ago" fresh
}

// ---------------------------------------------------------------- tooltips

// One tooltip for the whole page. It appears next to anything with data-tip="..."
// when the mouse is on it, when you Tab to it, or when you tap it. It goes above
// if there is room, else below, and never off the edge of the screen.
function setupTooltips() {
  const tip = $("tip");
  const show = (el) => {
    tip.textContent = el.dataset.tip;
    tip.hidden = false;
    const target = el.getBoundingClientRect(), box = tip.getBoundingClientRect();
    const above = target.top - box.height - 8;
    const left = target.left + target.width / 2 - box.width / 2;
    tip.style.top = `${above >= 4 ? above : target.bottom + 8}px`;
    tip.style.left = `${Math.max(8, Math.min(left, innerWidth - box.width - 8))}px`;
  };
  const hide = () => (tip.hidden = true);
  const tipOwner = (e) => (e.target instanceof Element ? e.target.closest("[data-tip]") : null);

  for (const [on, off] of [["mouseover", "mouseout"], ["focusin", "focusout"]]) {
    document.addEventListener(on, (e) => { const el = tipOwner(e); if (el) show(el); });
    document.addEventListener(off, (e) => { if (tipOwner(e)) hide(); });
  }
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") hide(); });
  window.addEventListener("scroll", hide, true);
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
    button.setAttribute("aria-label", button.title);
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
setupTooltips();

(async function start() {
  try {
    await handleRedirect();               // just came back from Cognito?
    if (!(await getToken())) return login();
    $("username").textContent = currentUser();
    wireUp();
    await loadFindings();
  } catch (e) {
    // The login didn't finish. Don't leave an empty page: say why, and offer to start again.
    $("findings-body").innerHTML = `
      <tr><td colspan="7" class="load-error">
        <b>Login didn't finish.</b>
        <div>${esc(friendly(e))}</div>
        <button class="retry primary">Log in again</button>
      </td></tr>`;
    $("findings-body").querySelector(".retry").onclick = login;
  }
})();
