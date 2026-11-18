"use strict";

/* ------------------------------------------------------------------ helpers */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const main = $("#main");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const enc = encodeURIComponent;
const nf = new Intl.NumberFormat();

const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_LABEL = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", INFO: "Info", NONE: "None" };
const DARK_INK = new Set(["HIGH", "MEDIUM", "INFO", "mitigated"]);
const STATUS = {
  public: { label: "Public", cls: "crit" },
  accepted: { label: "Accepted", cls: "neutral" },
  mitigated: { label: "Mitigated", cls: "warn" },
  private: { label: "Private", cls: "good" },
};
const VERDICT = {
  DATA_ACCESSED: { label: "Data accessed", cls: "crit", icon: "!" },
  EXPOSURE_PROBED: { label: "Probed", cls: "warn", icon: "!" },
  NO_EVIDENCE_OF_ACCESS: { label: "No evidence of access", cls: "good", icon: "✓" },
  NO_LOGS_AVAILABLE: { label: "No logs available", cls: "warn", icon: "?" },
};
const CLASSIFICATION = {
  RESTRICTED: { label: "Restricted", cls: "crit", text: "Secrets or credentials found: anyone who downloaded them may be able to access other systems." },
  CONFIDENTIAL: { label: "Confidential", cls: "crit", text: "Personal or business-sensitive data found." },
  INTERNAL: { label: "Internal", cls: "warn", text: "No secrets or personal data detected, but files that usually hold internal data are present." },
  NONE_FOUND: { label: "Nothing sensitive", cls: "good", text: "Nothing sensitive was detected in the sampled objects." },
};
const INCIDENT_STATUS = {
  CONTAINED: "good", NO_EXPOSURE: "good", OPEN: "crit", REMEDIATION_FAILED: "crit", REMEDIATION_PLANNED: "warn", ROLLED_BACK: "warn",
};
const FW_SHORT = { NIST: "NIST", CIS8: "CIS v8", ISO: "ISO", CISB: "CIS" };

function store(key, value) { try { localStorage.setItem(key, value); } catch { /* storage unavailable */ } }
function recall(key) { try { return localStorage.getItem(key); } catch { return null; } }

async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: { "X-CloudDetectX": "1", ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (!res.ok) {
    const detail = data && data.detail;
    throw new Error(typeof detail === "string" ? detail : detail ? JSON.stringify(detail) : `HTTP ${res.status}`);
  }
  return data;
}

async function runJob(jobId, onUpdate) {
  for (;;) {
    const job = await api(`/api/jobs/${jobId}`);
    if (onUpdate) onUpdate(job);
    if (job.status === "done") return job.result;
    if (job.status === "error") throw new Error(job.error);
    await sleep(700);
  }
}
const logInto = (el) => (j) => { if (!el) return; el.hidden = false; el.textContent = j.progress.map((p) => p.msg).join("\n"); el.scrollTop = el.scrollHeight; };

function toast(msg, kind = "") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), kind === "err" ? 8000 : 4000);
}

function timeAgo(iso) {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleString();
}
const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString() : "-");
function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`;
}

const badge = (label, cls) => `<span class="badge ${cls}">${esc(label)}</span>`;
const statusBadge = (st) => badge(STATUS[st]?.label || st, STATUS[st]?.cls || "neutral");
const sevTag = (s) => (s ? `<span class="sev sev-${s}"><i></i>${SEV_LABEL[s] || s}</span>` : `<span class="muted">-</span>`);
const verdictBadge = (v) => (v ? badge(VERDICT[v].label, VERDICT[v].cls) : `<span class="muted">-</span>`);
const classBadge = (c) => (c ? badge(CLASSIFICATION[c].label, CLASSIFICATION[c].cls) : `<span class="muted">not scanned</span>`);
const spinner = `<span class="spinner" aria-hidden="true"></span>`;
const errorBox = (msg) => `<div class="banner crit"><div class="icon">!</div><div><strong>Something went wrong</strong>${esc(msg)}</div></div>`;
const riskLevel = (score) => (score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 30 ? "MEDIUM" : score > 0 ? "LOW" : "NONE");
const riskCell = (score) => `<span class="risk sev-${riskLevel(score)}" data-tip="Risk ${score}/100 (${SEV_LABEL[riskLevel(score)]})">
  <span class="risk-num">${score}</span><span class="meter"><i style="width:${Math.max(3, score)}%"></i></span></span>`;
const scoreClass = (s) => (s == null ? "" : s >= 80 ? "good" : s >= 50 ? "warn" : "crit");
const controlChip = (c) => `<span class="chip" data-tip="${esc(`${c.framework_name}: ${c.title}`)}">${esc(FW_SHORT[c.framework])} ${esc(c.id)}</span>`;

async function withBusy(btn, label, fn) {
  const original = btn ? btn.innerHTML : "";
  if (btn) { btn.disabled = true; btn.innerHTML = `${spinner} ${esc(label)}`; }
  try { return await fn(); } finally { if (btn && btn.isConnected) { btn.disabled = false; btn.innerHTML = original; } }
}

/* ------------------------------------------------------------------ tooltip */
const tip = $("#tip");
function showTip(text, x, y) {
  tip.textContent = text;
  tip.hidden = false;
  tip.style.left = `${Math.min(x + 14, window.innerWidth - tip.offsetWidth - 8)}px`;
  tip.style.top = `${y + 16}px`;
}
document.addEventListener("mouseover", (e) => {
  const el = e.target.closest("[data-tip]");
  if (el) { tip.textContent = el.dataset.tip; tip.hidden = false; } else if (!e.target.closest(".linechart")) tip.hidden = true;
});
document.addEventListener("mousemove", (e) => {
  if (tip.hidden || e.target.closest(".linechart")) return;
  showTip(tip.textContent, e.clientX, e.clientY);
});
document.addEventListener("focusin", (e) => {
  const el = e.target.closest("[data-tip]");
  if (!el) return;
  const r = el.getBoundingClientRect();
  showTip(el.dataset.tip, r.left - 14, r.bottom - 10);
});
document.addEventListener("focusout", () => { tip.hidden = true; });

/* ------------------------------------------------------------------ state */
const state = { status: null, cloud: null, filter: "all", query: "", fw: "all", cat: null, iamFilter: "flagged", iamQuery: "" };
const cloudInfo = (name = state.cloud) => state.status.clouds.find((c) => c.name === name);

async function refreshStatus() {
  state.status = await api("/api/status");
  if (!state.cloud) {
    const saved = recall("clouddetectx.cloud");
    state.cloud = state.status.clouds.some((c) => c.name === saved) ? saved : state.status.default_providers[0] || "aws";
  }
  renderSidebar();
}

function renderSidebar() {
  $("#clouds").innerHTML = state.status.clouds.map((c) => {
    const dot = c.connected ? "ok" : c.error ? "err" : "";
    const sub = c.connected ? (c.scanned_at ? `${c.counts.resources} resources · ${c.counts.public} public` : "connected, not scanned")
      : c.error ? "connection failed" : "not connected";
    const label = c.connected ? "connected" : c.error ? "error" : "not connected";
    return `<button class="cloud-btn ${c.name === state.cloud ? "active" : ""}" data-action="pick-cloud" data-cloud="${c.name}">
      <span class="dot ${dot}" aria-label="${label}"></span>
      <span class="name">${esc(c.display)}<small>${esc(sub)}</small></span>
      ${c.counts.public ? badge(c.counts.public, "crit") : ""}</button>`;
  }).join("");
  $("#foot").innerHTML = `CloudDetectX v${esc(state.status.version)} · local only`;
}

/* ------------------------------------------------------------------ router */
async function route() {
  const parts = (location.hash.slice(1) || "/dashboard").split("/").filter(Boolean).map(decodeURIComponent);
  const page = parts[0] || "dashboard";
  $$(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.nav === page || (page === "r" && a.dataset.nav === "dashboard")));
  tip.hidden = true;
  try {
    if (!state.status) await refreshStatus();
    if (!state.status.configured && page !== "setup" && page !== "settings" && !recall("clouddetectx.setup-skipped")) {
      location.hash = "#/setup";
      return;
    }
    if (page === "setup") await renderSetup(parts[1] || "clouds");
    else if (page === "dashboard") await renderDashboard();
    else if (page === "r") await renderResource(parts[1], parts[2], parts[3] || "findings");
    else if (page === "respond") await renderRespond();
    else if (page === "iam") await renderIam();
    else if (page === "compliance") await renderCompliance();
    else if (page === "history") await renderHistory();
    else if (page === "reports") await (parts[1] ? renderReport(parts[1]) : renderReports());
    else if (page === "settings") await renderSettings();
    else location.hash = "#/dashboard";
  } catch (e) {
    main.innerHTML = errorBox(e.message);
  }
}
window.addEventListener("hashchange", route);

/* ------------------------------------------------------------------ actions (event delegation) */
const actions = {};
document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-action]");
  if (!el || el.disabled) return;
  const fn = actions[el.dataset.action];
  if (fn) { e.preventDefault(); fn(el, e); }
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && e.target.matches("tr[data-action], li[data-action]")) actions[e.target.dataset.action](e.target);
});

actions["pick-cloud"] = (el) => {
  state.cloud = el.dataset.cloud;
  state.cat = null;
  store("clouddetectx.cloud", state.cloud);
  renderSidebar();
  if (["#/dashboard", "#/compliance", "#/history", "#/respond", "#/iam"].some((h) => location.hash.startsWith(h))) route();
  else location.hash = "#/dashboard";
};

actions.connect = async (el) => {
  await withBusy(el, "Connecting", async () => {
    try {
      await api(`/api/clouds/${state.cloud}/connect`, { method: "POST" });
      toast(`Connected to ${cloudInfo().display}`, "ok");
    } catch (e) { toast(e.message, "err"); }
    await refreshStatus();
    route();
  });
};

actions.scan = async (el) => {
  const box = $("#scan-progress");
  await withBusy(el, "Scanning", async () => {
    try {
      const scope = $("#scope");
      const { job } = await api(`/api/clouds/${state.cloud}/scan`, { method: "POST", body: { all_accounts: scope ? scope.value === "all" : false } });
      await runJob(job, (j) => { if (box) { box.hidden = false; box.textContent = j.progress.slice(-1)[0]?.msg || "Starting..."; } });
      toast("Scan complete", "ok");
    } catch (e) { toast(e.message, "err"); }
    await refreshStatus();
    route();
  });
};

/* ------------------------------------------------------------------ charts */
function segBar(parts, { thin = false, unit = "" } = {}) {
  const total = parts.reduce((a, p) => a + p.value, 0);
  if (!total) return `<div class="empty-chart">Nothing to show yet.</div>`;
  const segs = parts.filter((p) => p.value > 0).map((p) => {
    const share = Math.round((p.value / total) * 100);
    const tipText = `${p.label}: ${nf.format(p.value)}${unit} (${share}%)`;
    const text = !thin && share >= 7 ? nf.format(p.value) : "";
    return `<div class="seg ${p.cls} ${DARK_INK.has(p.key) ? "dark-ink" : ""}" style="flex-grow:${p.value}"
      data-tip="${esc(tipText)}" tabindex="0" aria-label="${esc(tipText)}">${text}</div>`;
  }).join("");
  const legend = parts.map((p) => `<span class="${p.cls}"><i class="swatch"></i>${esc(p.label)}</span>`).join("");
  const rows = parts.map((p) => `<tr><td>${esc(p.label)}</td><td class="num">${nf.format(p.value)}</td>
    <td class="num">${total ? Math.round((p.value / total) * 100) : 0}%</td></tr>`).join("");
  return `<div class="segbar ${thin ? "thin" : ""}" role="img" aria-label="${esc(parts.map((p) => `${p.label} ${p.value}`).join(", "))}">${segs}</div>
    <div class="legend">${legend}</div>
    <details class="table-view"><summary>Show as table</summary><table><thead><tr><th>Category</th><th class="num">Count</th><th class="num">Share</th></tr></thead><tbody>${rows}</tbody></table></details>`;
}
const severityParts = (counts) => SEV.map((s) => ({ key: s, label: SEV_LABEL[s], value: counts[s] || 0, cls: `sev-${s}` }));
const exposureParts = (c) => ["public", "accepted", "mitigated", "private"].map((st) => ({ key: st, label: STATUS[st].label, value: c[st] || 0, cls: `st-${st}` }));

/* Single-series line chart (inline SVG) with crosshair + tooltip and a table view. */
function lineChart(points, { label, max = null, cls = "", fmt = (v) => nf.format(v), wide = false } = {}) {
  if (points.length < 2) return `<div class="empty-chart">Needs at least two scans. Scan again later to see the trend.</div>`;
  // Coordinate width roughly matches the rendered width so text and strokes stay at their real size.
  const W = wide ? 1080 : 520, H = 190, L = 36, R = 12, T = 12, B = 26;
  const top = max ?? Math.max(1, ...points.map((p) => p.v));
  const yMax = max ?? Math.ceil(top * 1.15);
  // Time-proportional x so uneven scan intervals aren't drawn as evenly spaced; index fallback if all equal.
  const ts = points.map((p) => new Date(p.t).getTime());
  const t0 = ts[0], span = ts[ts.length - 1] - t0;
  const frac = (i) => (span > 0 && ts.every(Number.isFinite) ? (ts[i] - t0) / span : i / (points.length - 1));
  const x = (i) => L + frac(i) * (W - L - R);
  const xs = points.map((_, i) => Number(x(i).toFixed(1)));
  const y = (v) => T + (H - T - B) * (1 - v / yMax);
  const path = points.map((p, i) => `${i ? "L" : "M"}${xs[i]},${y(p.v).toFixed(1)}`).join(" ");
  const ticks = [0, yMax / 2, yMax].map((t) => Math.round(t));
  const id = `lc${Math.random().toString(36).slice(2, 8)}`;
  const last = points[points.length - 1];
  const rows = points.map((p) => `<tr><td>${esc(fmtDate(p.t))}</td><td class="num">${esc(fmt(p.v))}</td></tr>`).join("");
  return `<div class="linechart ${cls}" id="${id}" data-points='${esc(JSON.stringify(points))}' data-xs='${esc(JSON.stringify(xs))}' data-label="${esc(label)}">
    <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(`${label}: latest ${fmt(last.v)}`)}">
      ${ticks.map((t) => `<line class="grid" x1="${L}" x2="${W - R}" y1="${y(t)}" y2="${y(t)}"/><text class="tick" x="${L - 6}" y="${y(t) + 4}" text-anchor="end">${t}</text>`).join("")}
      <text class="tick" x="${L}" y="${H - 6}">${esc(new Date(points[0].t).toLocaleDateString())}</text>
      <text class="tick" x="${W - R}" y="${H - 6}" text-anchor="end">${esc(new Date(last.t).toLocaleDateString())}</text>
      <path class="line" d="${path}"/>
      <circle class="dot-last" cx="${xs[xs.length - 1]}" cy="${y(last.v)}" r="4.5"/>
      <line class="cross" x1="0" x2="0" y1="${T}" y2="${H - B}" visibility="hidden"/>
      <circle class="dot-hover" r="5" visibility="hidden"/>
      <rect class="hit" x="${L}" y="0" width="${W - L - R}" height="${H}" fill="transparent"/>
    </svg></div>
    <details class="table-view"><summary>Show as table</summary><table><thead><tr><th>Scan</th><th class="num">${esc(label)}</th></tr></thead><tbody>${rows}</tbody></table></details>`;
}

function bindLineCharts(root = main) {
  $$(".linechart", root).forEach((box) => {
    const pts = JSON.parse(box.dataset.points);
    const xs = JSON.parse(box.dataset.xs);
    const svg = $("svg", box);
    const vb = svg.viewBox.baseVal;
    const T = 12, B = 26;
    const yMax = Number(($$("text.tick", svg)[2] || {}).textContent) || 1;
    const cross = $(".cross", svg), dot = $(".dot-hover", svg);
    const move = (e) => {
      const r = svg.getBoundingClientRect();
      const px = ((e.clientX - r.left) / r.width) * vb.width;
      let i = 0;
      xs.forEach((v, k) => { if (Math.abs(v - px) < Math.abs(xs[i] - px)) i = k; });
      const cx = xs[i];
      const cy = T + (vb.height - T - B) * (1 - pts[i].v / yMax);
      cross.setAttribute("x1", cx); cross.setAttribute("x2", cx); cross.setAttribute("visibility", "visible");
      dot.setAttribute("cx", cx); dot.setAttribute("cy", cy); dot.setAttribute("visibility", "visible");
      showTip(`${fmtDate(pts[i].t)}: ${box.dataset.label} ${nf.format(pts[i].v)}`, e.clientX, e.clientY);
    };
    svg.addEventListener("mousemove", move);
    svg.addEventListener("mouseleave", () => { cross.setAttribute("visibility", "hidden"); dot.setAttribute("visibility", "hidden"); tip.hidden = true; });
  });
}

/* ------------------------------------------------------------------ dashboard */
function driftBanner(c) {
  const d = c.drift;
  const parts = [];
  if (c.alert_error) parts.push(`<div class="banner crit"><div class="icon">!</div><div><strong>Alert delivery failed</strong>${esc(c.alert_error)}</div></div>`);
  if (!d || !d.previous_at || !d.changed) return parts.join("");
  const list = (arr) => arr.slice(0, 6).map((n) => `<b>${esc(n)}</b>`).join(", ") + (arr.length > 6 ? ` +${arr.length - 6}` : "");
  const lines = [];
  if (d.new_public.length) lines.push(`${badge("Newly public", "crit")} ${list(d.new_public)}`);
  if (d.resolved.length) lines.push(`${badge("Fixed", "good")} ${list(d.resolved)}`);
  if ((d.accepted || []).length) lines.push(`${badge("Accepted", "neutral")} ${list(d.accepted)}`);
  if (d.new_resources.length) lines.push(`${badge("New", "neutral")} ${list(d.new_resources)}`);
  if (d.removed_resources.length) lines.push(`${badge("Removed", "neutral")} ${list(d.removed_resources)}`);
  if (d.risk_increased.length) lines.push(`${badge("Risk up", "warn")} ${d.risk_increased.slice(0, 6).map((x) => `<b>${esc(x.name)}</b> ${x.from}→${x.to}`).join(", ")}`);
  parts.push(`<div class="banner ${d.new_public.length ? "crit" : "info"}"><div class="icon">Δ</div><div>
    <strong>Changes since the previous scan (${esc(timeAgo(d.previous_at))})</strong>
    <div class="stack-tight">${lines.map((l) => `<div>${l}</div>`).join("")}</div></div></div>`);
  return parts.join("");
}

async function renderDashboard() {
  const c = cloudInfo();
  let resources = [];
  let trend = [];
  if (c.scanned_at) {
    [resources, trend] = await Promise.all([
      api(`/api/clouds/${c.name}/resources`).then((r) => r.resources),
      api(`/api/clouds/${c.name}/history`).then((r) => r.scans).catch(() => []),
    ]);
  }
  const counts = c.counts;
  const head = `<div class="page-head">
    <div><h1>${esc(c.display)}</h1>
      <div class="sub">${c.connected ? esc(c.account) : c.error ? `<span style="color:var(--critical)">${esc(c.error)}</span>` : esc(c.hint || "Not connected yet.")}
      ${c.scanned_at ? ` · scanned ${esc(timeAgo(c.scanned_at))}` : ""}</div></div>
    <div class="actions">
      ${c.connected ? "" : `<button class="btn" data-action="connect">Connect</button>`}
      ${c.error || c.hint ? `<a class="btn" href="#/settings">Fix in Settings</a>` : ""}
      ${c.scanned_at ? exportMenu(c.name) : ""}
      <select id="scope" aria-label="Scan scope" data-tip="All accounts = AWS Organizations accounts, Azure subscriptions or GCP projects you can reach">
        <option value="account" ${c.scope !== "all" ? "selected" : ""}>This account</option>
        <option value="all" ${c.scope === "all" ? "selected" : ""}>All accounts</option></select>
      <button class="btn primary" data-action="scan">${c.scanned_at ? "Scan again" : "Scan now"}</button>
    </div></div>
    <div id="scan-progress" class="log" hidden></div>
    ${c.restored ? `<div class="banner info" style="margin-bottom:12px"><div class="icon">↺</div><div><strong>Showing the last saved scan (${esc(timeAgo(c.scanned_at))})</strong>
      Results were kept from before the dashboard restarted. Scan again for current data.</div></div>` : ""}
    ${c.scope === "all" && Object.keys(c.account_errors || {}).length ? `<div class="banner warn" style="margin-bottom:12px"><div class="icon">!</div><div>
      <strong>${Object.keys(c.account_errors).length} account(s) could not be scanned</strong>${Object.entries(c.account_errors).slice(0, 4).map(([a, e]) => `${esc(a)}: ${esc(e)}`).join("<br>")}</div></div>` : ""}`;

  if (!c.scanned_at) {
    main.innerHTML = `${head}<div class="card empty"><h2>No scan yet for ${esc(c.display)}</h2>
      <p>A scan reads the configuration of every bucket or storage account, scores its risk and records it for drift detection. It is read-only.</p>
      <button class="btn primary" data-action="scan">Scan now</button></div>${overviewCard()}`;
    return;
  }

  const ov = await api(`/api/clouds/${c.name}/overview`).catch(() => null);
  const score = c.posture_score;
  const noun = c.name === "azure" ? "storage accounts" : "buckets";
  const delta = ov && ov.score_delta;
  const deltaHtml = delta == null ? `<span class="muted">First recorded scan</span>`
    : delta === 0 ? `<span class="muted">No change since last scan</span>`
    : `<span class="delta ${delta > 0 ? "up" : "down"}">${delta > 0 ? "▲" : "▼"} ${Math.abs(delta)}</span> <span class="muted">since last scan</span>`;
  const catFilter = state.cat && ov ? ov.categories.find((k) => k.key === state.cat) : null;
  main.innerHTML = `${head}
    <div class="stack">${driftBanner(c)}</div>
    <section class="kpis dash" style="margin-top:16px">
      <div class="kpi score-tile">${gauge(score, c.grade)}
        <div><div class="label">Security score</div>
          <div class="note" style="margin-top:4px">${score == null ? "" : badge(score >= 80 ? "Good" : score >= 50 ? "Needs work" : "At risk", scoreClass(score))}</div>
          <div class="note">${deltaHtml}</div>
          <div class="note"><span data-tip="100 minus a blend of the worst resource risk (70%) and the average risk (30%). Grades: A 90+, B 80+, C 65+, D 50+, F below." tabindex="0" class="muted u">How is this scored?</span></div></div>
      </div>
      <div class="kpi hero ${counts.public ? "alert" : ""}">
        <div class="label">Publicly exposed</div>
        <div class="value"><span data-count="${counts.public}">${nf.format(counts.public)}</span></div>
        <div class="note">${counts.public ? badge("Action needed", "crit") : badge("No public exposure", "good")}</div>
      </div>
      <div class="kpi"><div class="label">Resources scanned</div><div class="value"><span data-count="${counts.resources}">${nf.format(counts.resources)}</span></div>
        <div class="note">${nf.format(counts.mitigated)} mitigated by guardrails</div></div>
      <div class="kpi"><div class="label">Critical findings</div><div class="value"><span data-count="${c.severity_counts.CRITICAL}">${nf.format(c.severity_counts.CRITICAL)}</span></div>
        <div class="note">${nf.format(c.severity_counts.HIGH)} high · ${nf.format(c.severity_counts.MEDIUM)} medium</div></div>
    </section>
    ${ov ? `<section class="card" style="margin-top:16px"><div class="card-head"><h2>Security posture</h2>
        <span class="muted small">Select a category to see the ${esc(noun)} that fail it</span></div>
        <div class="cats">${ov.categories.map((k) => categoryTile(k, noun)).join("")}</div></section>
      <section class="grid2">
        <div class="card"><div class="card-head"><h2>Fix these first</h2>${counts.public ? `<a class="btn small danger" href="#/respond">Respond to ${counts.public} exposed</a>` : ""}</div>${priorityList(ov.priorities)}</div>
        <div class="card"><div class="card-head"><h2>Compliance at a glance</h2><a href="#/compliance" class="small-link">Details</a></div>
          ${complianceBars(ov.compliance)}${topControls(ov.top_controls)}
          <p class="muted small" style="margin:12px 0 0">Bars show resource-level checks passing per framework. <a href="#" data-action="compliance-report">Generate a compliance report</a></p></div>
      </section>` : ""}
    <section class="grid2">
      <div class="card"><h2>Findings by severity</h2>${segBar(severityParts(c.severity_counts), { unit: " findings" })}</div>
      <div class="card"><h2>Exposure across ${esc(noun)}</h2>${segBar(exposureParts(counts), { unit: " resources" })}</div>
    </section>
    <section class="card" style="margin-top:16px"><div class="card-head"><h2>Publicly exposed ${esc(noun)} over time</h2><a href="#/history" class="small-link">History</a></div>
      ${lineChart(trend.map((s) => ({ t: s.scanned_at, v: s.public })), { label: "public", cls: "crit-line", wide: true })}</section>
    <section class="card" style="margin-top:16px" id="resources">
      <div class="card-head"><h2>Resources</h2></div>
      <div class="toolbar">
        <input type="search" id="q" placeholder="Filter by name or region" value="${esc(state.query)}" aria-label="Filter resources">
        <div class="seg-ctrl" role="group" aria-label="Status filter">
          ${["all", "public", "accepted", "mitigated", "private"].filter((f) => f !== "accepted" || counts.accepted).map((f) => `<button data-action="filter" data-filter="${f}" class="${state.filter === f ? "on" : ""}">
            ${f === "all" ? `All (${counts.resources})` : `${STATUS[f].label} (${counts[f]})`}</button>`).join("")}
        </div>
        ${catFilter ? `<span class="chip on">Failing: ${esc(catFilter.label)} <button class="x" data-action="cat-clear" aria-label="Clear category filter">×</button></span>` : ""}
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>Status</th><th>Name</th>${c.scope === "all" ? "<th>Account</th>" : ""}<th>Location</th><th>Risk</th><th>Highest severity</th><th>Encryption</th><th>Data</th><th>Access verdict</th></tr></thead>
        <tbody id="rows"></tbody></table></div>
    </section>
    ${overviewCard()}`;

  state.rows = resources;
  drawRows();
  bindLineCharts();
  animateIn();
  $("#q").addEventListener("input", (e) => { state.query = e.target.value; drawRows(); });
}

/* -- dashboard pieces */
const ICONS = {
  public: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.2 3 14.8 0 18M12 3c-3 3.2-3 14.8 0 18"/>',
  iam: '<circle cx="8" cy="15" r="4"/><path d="m11 12 8.5-8.5M16 7l3 3M13.5 9.5l2 2"/>',
  encryption: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  logging: '<path d="M9 6h11M9 12h11M9 18h11"/><circle cx="4.5" cy="6" r="1"/><circle cx="4.5" cy="12" r="1"/><circle cx="4.5" cy="18" r="1"/>',
  backup: '<path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1L3.5 8.5"/><path d="M3.5 3.5v5h5M12 7.5V12l3 2"/>',
  data: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h4"/>',
};
const icon = (k) => `<svg class="ico" viewBox="0 0 24 24" aria-hidden="true">${ICONS[k] || ""}</svg>`;

function gauge(score, grade) {
  const r = 42, circ = 2 * Math.PI * r;
  const offset = circ * (1 - (score == null ? 0 : score / 100));
  return `<div class="gauge ${scoreClass(score)}" role="img" aria-label="Security score ${score ?? "not available"} out of 100, grade ${grade ?? "not available"}">
    <svg viewBox="0 0 100 100"><circle class="track" cx="50" cy="50" r="${r}"/>
      <circle class="arc" cx="50" cy="50" r="${r}" stroke-dasharray="${circ.toFixed(1)}" stroke-dashoffset="${circ.toFixed(1)}"
        data-offset="${offset.toFixed(1)}" transform="rotate(-90 50 50)"/></svg>
    <div class="gauge-c"><span class="num" ${score == null ? "" : `data-count="${score}"`}>${score ?? "-"}</span><span class="grade">${grade ? `Grade ${esc(grade)}` : "/100"}</span></div></div>`;
}

function categoryTile(k, noun) {
  if (!k.checked) {
    return `<div class="cat off">${icon(k.key)}<div class="cat-b"><div class="cat-l">${esc(k.label)}</div>
      <div class="cat-v muted">${k.key === "data" ? "Run data discovery on a resource" : "Not assessed for this cloud"}</div></div></div>`;
  }
  const iam = k.principals != null;
  const accountOnly = !iam && !k.resources_total;
  const total = k.resources_total, pass = total - k.resources_failing;
  const pct = total ? Math.round((100 * pass) / total) : null;
  const ok = !k.findings;
  const value = iam ? `${nf.format(k.risky_principals)}<span class="of">/${nf.format(k.principals)} principals flagged</span>`
    : accountOnly ? `${nf.format(k.account_findings)}<span class="of"> account-wide issue${k.account_findings === 1 ? "" : "s"}</span>`
    : `${nf.format(pass)}<span class="of">/${nf.format(total)} ${esc(noun)} pass</span>`;
  const acctLine = !iam && !accountOnly && k.account_findings ? `<div class="cat-a">+ ${k.account_findings} account-wide issue${k.account_findings === 1 ? "" : "s"}</div>` : "";
  const tipText = ok ? `${k.label}: no failing checks` : `${k.label}: ${k.findings} failing finding(s)${total ? `, ${k.resources_failing} of ${total} ${noun} affected` : ""}`;
  return `<button class="cat ${ok ? "ok" : `bad sev-${k.worst}`} ${state.cat === k.key ? "sel" : ""}" data-action="${iam || accountOnly ? "go-iam" : "cat"}" data-cat="${k.key}" data-tip="${esc(tipText)}">
    ${icon(k.key)}<div class="cat-b"><div class="cat-l">${esc(k.label)}</div>
    <div class="cat-v">${value}</div>${acctLine}
    ${pct != null && !iam ? `<div class="meter"><i style="width:${Math.max(2, pct)}%"></i></div>` : ""}
    <div class="cat-s">${ok ? badge("All checks pass", "good") : sevTag(k.worst)}</div></div></button>`;
}

function priorityList(items) {
  if (!items.length) return `<div class="all-clear">${badge("All clear", "good")} Nothing urgent: no public exposure and no medium-or-higher findings.</div>`;
  return `<ol class="prio">${items.map((p, i) => `<li data-action="${p.kind === "resource" ? "open-resource" : "go-iam"}" data-name="${esc(p.name)}" tabindex="0" class="sev-${p.severity}">
      <span class="prio-n">${i + 1}</span>
      <div class="prio-b"><div class="prio-t"><strong>${esc(p.name)}</strong> ${sevTag(p.severity)} ${p.exposed ? badge("Public", "crit") : ""}</div>
        <div class="prio-f">${esc(p.title)}</div><div class="prio-fix">${esc(p.recommendation)}</div></div>
      ${p.risk != null ? `<div class="prio-r">${riskCell(p.risk)}</div>` : ""}</li>`).join("")}</ol>`;
}

const rateClass = (pct) => (pct >= 80 ? "m-good" : pct >= 50 ? "m-warn" : "m-crit");

function complianceBars(comp) {
  return `<div class="cbars">${Object.entries(comp).map(([k, v]) => {
    const pct = v.pass_rate ?? 0;
    const tipText = `${v.name}: ${v.checks_total - v.checks_failing} of ${v.checks_total} resource checks pass; ${v.passing} of ${v.assessed} controls pass on every resource`;
    return `<div class="cbar" data-tip="${esc(tipText)}">
      <div class="cbar-h"><span>${esc(v.name)}</span><span><strong>${pct}%</strong> <span class="muted">· ${v.passing}/${v.assessed} controls fully pass</span></span></div>
      <div class="meter big ${rateClass(pct)}"><i style="width:${Math.max(2, pct)}%"></i></div></div>`;
  }).join("")}</div>`;
}

function topControls(rows) {
  if (!rows || !rows.length) return "";
  return `<h3 style="margin:18px 0 6px">Most affected controls</h3><ul class="plain tctl">${rows.map((r) =>
    `<li>${sevTag(r.worst)} <span class="chip">${esc(FW_SHORT[r.framework])} ${esc(r.id)}</span> ${esc(r.title)} <span class="muted">· ${r.resources} resource(s)</span></li>`).join("")}</ul>`;
}

function encCell(e) {
  if (!e) return `<span class="muted">-</span>`;
  const rest = e.at_rest ? e.at_rest.replace(" (S3-managed keys)", "") : null;
  return `<span class="enc ${rest && e.in_transit_enforced ? "ok" : "gap"}" data-tip="${esc(`At rest: ${e.at_rest || "no default encryption"}. In transit: ${e.in_transit_enforced ? "HTTPS required" : "HTTP allowed"}.`)}">
    ${rest ? esc(rest) : "None"} · ${e.in_transit_enforced ? "HTTPS" : "HTTP allowed"}</span>`;
}

function animateIn(root = main) {
  let reduce = false;
  try { reduce = matchMedia("(prefers-reduced-motion: reduce)").matches; } catch { /* old browser */ }
  $$(".gauge .arc", root).forEach((arc) => {
    if (reduce) { arc.style.transition = "none"; arc.style.strokeDashoffset = arc.dataset.offset; return; }
    requestAnimationFrame(() => requestAnimationFrame(() => { arc.style.strokeDashoffset = arc.dataset.offset; }));
  });
  if (reduce) return;
  $$("[data-count]", root).forEach((el) => {
    const end = Number(el.dataset.count);
    if (!Number.isFinite(end) || end <= 0) return;
    const t0 = performance.now();
    const step = (t) => {
      const k = Math.min(1, (t - t0) / 700);
      el.textContent = nf.format(Math.round(end * (1 - (1 - k) ** 3)));
      if (k < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  });
}

actions.cat = (el) => {
  state.cat = state.cat === el.dataset.cat ? null : el.dataset.cat;
  renderDashboard().then(() => { if (state.cat) $("#resources").scrollIntoView({ behavior: "smooth", block: "start" }); });
};
actions["cat-clear"] = () => { state.cat = null; renderDashboard(); };
actions["go-iam"] = () => { location.hash = "#/iam"; };
actions["compliance-report"] = async (el) => {
  try {
    const r = await api(`/api/clouds/${state.cloud}/compliance/report`, { method: "POST" });
    toast("Compliance report saved", "ok");
    location.hash = `#/reports/${enc(r.report_id)}`;
  } catch (e) { toast(e.message, "err"); }
};

function drawRows() {
  const order = { public: 0, accepted: 1, mitigated: 2, private: 3 };
  const q = state.query.trim().toLowerCase();
  const rows = (state.rows || [])
    .filter((r) => state.filter === "all" || r.status === state.filter)
    .filter((r) => !state.cat || (r.failing_categories || []).includes(state.cat))
    .filter((r) => !q || r.name.toLowerCase().includes(q) || (r.location || "").toLowerCase().includes(q))
    .sort((a, b) => order[a.status] - order[b.status] || b.risk - a.risk || a.name.localeCompare(b.name));
  $("#rows").innerHTML = rows.length ? rows.map((r) => `<tr class="clickable" data-action="open-resource" data-name="${esc(r.name)}" tabindex="0">
      <td>${statusBadge(r.status)}${r.verified_public ? ` <span class="chip crit" data-tip="Confirmed by an anonymous request from the internet">verified</span>` : ""}</td>
      <td><strong>${esc(r.name)}</strong>${r.accepted ? ` <span class="chip" data-tip="${r.accepted} finding(s) accepted by waiver">${r.accepted} accepted</span>` : ""}</td>
      ${cloudInfo().scope === "all" ? `<td class="mono small">${esc(r.account || "-")}</td>` : ""}
      <td class="secondary">${esc(r.location || "-")}</td>
      <td>${riskCell(r.risk)}</td>
      <td>${sevTag(r.top_severity)}</td>
      <td>${encCell(r.encryption)}</td>
      <td>${classBadge(r.classification)}</td>
      <td>${verdictBadge(r.verdict)}</td></tr>`).join("")
    : `<tr><td colspan="9" class="muted">No resources match.</td></tr>`;
}

actions.filter = (el) => {
  state.filter = el.dataset.filter;
  $$(".seg-ctrl button").forEach((b) => b.classList.toggle("on", b === el));
  drawRows();
};
actions["open-resource"] = (el) => { location.hash = `#/r/${state.cloud}/${enc(el.dataset.name)}`; };

function overviewCard() {
  const rows = state.status.clouds.map((c) => `<tr class="clickable" data-action="pick-cloud" data-cloud="${c.name}">
    <td><strong>${esc(c.display)}</strong></td>
    <td>${c.connected ? badge("Connected", "good") : c.error ? badge("Error", "crit") : badge("Not connected", "neutral")}</td>
    <td class="num">${c.scanned_at ? nf.format(c.counts.resources) : "-"}</td>
    <td class="num">${c.scanned_at ? nf.format(c.counts.public) : "-"}</td>
    <td class="num">${c.posture_score == null ? "-" : c.posture_score}</td>
    <td style="min-width:160px">${c.scanned_at && c.counts.resources ? segBarThin(c.counts) : `<span class="muted">not scanned</span>`}</td>
    <td class="secondary nowrap">${esc(timeAgo(c.scanned_at))}</td></tr>`).join("");
  return `<section class="card" style="margin-top:16px"><h2>All clouds</h2><div class="table-wrap"><table>
    <thead><tr><th>Cloud</th><th>Connection</th><th class="num">Resources</th><th class="num">Public</th><th class="num">Score</th><th>Exposure</th><th>Last scan</th></tr></thead>
    <tbody>${rows}</tbody></table></div>
    <div class="legend" style="margin-top:8px">${exposureParts({}).map((p) => `<span class="${p.cls}"><i class="swatch"></i>${p.label}</span>`).join("")}</div></section>`;
}

function segBarThin(counts) {
  const parts = exposureParts(counts);
  const total = parts.reduce((a, p) => a + p.value, 0);
  return `<div class="segbar thin" role="img" aria-label="${esc(parts.map((p) => `${p.label} ${p.value}`).join(", "))}">${parts.filter((p) => p.value).map((p) =>
    `<div class="seg ${p.cls}" style="flex-grow:${p.value}" data-tip="${esc(`${p.label}: ${p.value} (${Math.round((p.value / total) * 100)}%)`)}"></div>`).join("")}</div>`;
}

/* ------------------------------------------------------------------ resource page */
const TABS = [["findings", "Findings"], ["access", "Access & encryption"], ["discover", "Data discovery"], ["verify", "Exposure test"], ["investigate", "Investigation"], ["remediate", "Remediation"]];

async function renderResource(cloud, name, tab) {
  if (cloud !== state.cloud) { state.cloud = cloud; store("clouddetectx.cloud", cloud); renderSidebar(); }
  let d;
  try {
    d = await api(`/api/clouds/${cloud}/resources/${enc(name)}`);
  } catch (e) {
    main.innerHTML = `<a class="crumb" href="#/dashboard">&larr; Dashboard</a>${errorBox(e.message)}`;
    return;
  }
  const s = d.summary;
  const base = `#/r/${cloud}/${enc(name)}`;
  main.innerHTML = `<a class="crumb" href="#/dashboard">&larr; ${esc(cloudInfo(cloud).display)}</a>
    <div class="page-head"><div>
      <h1>${esc(name)} ${statusBadge(s.status)}</h1>
      <div class="sub mono">${esc(s.resource_id)}</div>
      <div class="sub">${esc(s.kind)} · ${esc(s.location || "unknown location")} · ${s.findings} finding(s)
        ${s.classification ? ` · ${classBadge(s.classification)}` : ""}${s.verdict ? ` · ${verdictBadge(s.verdict)}` : ""}</div>
    </div><div class="actions">
      <div class="risk-pill sev-${d.risk.level}" data-tip="Risk score: see the Findings tab for the breakdown" tabindex="0">
        <span class="n">${d.risk.score}</span><span class="l">risk<br>${esc(SEV_LABEL[d.risk.level])}</span></div>
      <button class="btn" data-action="rescan" data-name="${esc(name)}">Re-scan</button>
      <button class="btn" data-action="save-report" data-name="${esc(name)}">Save report</button>
    </div></div>
    <nav class="tabs">${TABS.map(([k, l]) => `<a href="${base}/${k}" class="${tab === k ? "on" : ""}">${l}</a>`).join("")}</nav><div id="tab"></div>`;
  const box = $("#tab");
  if (tab === "investigate") renderInvestigateTab(box, name, d);
  else if (tab === "remediate") renderRemediateTab(box, name, d);
  else if (tab === "discover") renderDiscoverTab(box, name, d);
  else if (tab === "verify") renderVerifyTab(box, name, d);
  else if (tab === "access") renderAccessTab(box, name, d);
  else renderFindings(box, d);
}

function riskCard(risk) {
  return `<div class="card"><div class="card-head"><h2>Risk score</h2><span class="sev sev-${risk.level}"><i></i>${risk.score}/100 · ${SEV_LABEL[risk.level]}</span></div>
    <div class="meter big sev-${risk.level}"><i style="width:${Math.max(2, risk.score)}%"></i></div>
    ${risk.factors.length ? `<table style="margin-top:10px"><tbody>${risk.factors.map((f) =>
      `<tr><td class="num" style="width:60px">+${f.points}</td><td>${esc(f.reason)}</td></tr>`).join("")}</tbody></table>`
      : `<p class="muted">No risk factors.</p>`}
    <p class="muted" style="margin:10px 0 0">Run <strong>Data discovery</strong>, <strong>Exposure test</strong> and <strong>Investigation</strong> to refine the score.</p></div>`;
}

function renderFindings(box, d) {
  const findings = d.findings;
  box.innerHTML = riskCard(d.risk) + `<div style="margin-top:16px">${findings.length ? findings.map((f) => findingCard(f, true)).join("")
    : `<div class="card empty"><h2>No findings</h2><p>This resource passed every check${d.accepted.length ? " that isn't accepted" : ""}.</p></div>`}</div>
    ${acceptedList(d.accepted)}`;
}

actions.rescan = async (el) => {
  await withBusy(el, "Scanning", async () => {
    try { await api(`/api/clouds/${state.cloud}/resources/${enc(el.dataset.name)}/rescan`, { method: "POST" }); toast("Re-scanned", "ok"); }
    catch (e) { toast(e.message, "err"); }
    await refreshStatus();
    route();
  });
};
actions["save-report"] = async (el) => {
  await withBusy(el, "Saving", async () => {
    try {
      const r = await api(`/api/clouds/${state.cloud}/resources/${enc(el.dataset.name)}/report`, { method: "POST" });
      toast("Report saved", "ok");
      location.hash = `#/reports/${enc(r.report_id)}`;
    } catch (e) { toast(e.message, "err"); }
  });
};

/* -- data discovery */
function renderDiscoverTab(box, name, d) {
  box.innerHTML = `<div class="card"><h2>Sensitive data discovery</h2>
      <p class="secondary" style="margin-top:0">Samples objects and reads only the start of each one, looking for secrets (cloud keys, private keys, tokens, database URLs) and personal data (cards, SSN, Aadhaar, PAN, IBAN, emails).
      Everything runs on this computer, and matches are <strong>redacted</strong>: full values are never stored or shown.</p>
      <button class="btn primary" data-action="discover" data-name="${esc(name)}">${d.sensitive ? "Run again" : "Discover sensitive data"}</button>
      <span class="muted" style="margin-left:8px">Limits are in Settings &gt; Sensitive data discovery. Reading objects can incur request/egress costs.</span>
      <div id="disc-log" class="log" hidden></div></div>
    <div id="disc" class="stack" style="margin-top:16px">${d.sensitive ? sensitiveHtml(d.sensitive) : ""}</div>`;
}

actions.discover = async (el) => {
  await withBusy(el, "Discovering", async () => {
    try {
      const { job } = await api(`/api/clouds/${state.cloud}/resources/${enc(el.dataset.name)}/discover`, { method: "POST" });
      $("#disc").innerHTML = sensitiveHtml(await runJob(job, logInto($("#disc-log"))));
      await refreshStatus();
    } catch (e) { toast(e.message, "err"); }
  });
};

function sensitiveHtml(r) {
  const c = CLASSIFICATION[r.classification];
  const metric = (val, label) => `<div class="metric"><div class="v">${val}</div><div class="l">${esc(label)}</div></div>`;
  return `<div class="banner ${c.cls}"><div class="icon">${r.classification === "NONE_FOUND" ? "✓" : "!"}</div><div><strong>${esc(c.label)}</strong>${esc(c.text)}</div></div>
    <div class="card"><h2>Coverage</h2><div class="metrics">
      ${metric(nf.format(r.objects_listed), "objects listed")}${metric(nf.format(r.objects_scanned), "objects inspected")}
      ${metric(nf.format(r.objects_skipped), "skipped (binary/empty/unreadable)")}${metric(esc(fmtBytes(r.bytes_read)), "read")}
      ${metric(nf.format(r.secret_count), "secret matches")}${metric(nf.format(r.pii_count), "personal-data matches")}</div>
      ${r.notes.length ? `<ul class="plain" style="margin-top:10px">${r.notes.map((n) => `<li class="secondary">${esc(n)}</li>`).join("")}</ul>` : ""}</div>
    ${r.hits.length ? `<div class="card"><h2>What was found</h2><div class="table-wrap"><table>
      <thead><tr><th>Severity</th><th>Type</th><th class="num">Matches</th><th>Redacted samples</th><th>Found in</th></tr></thead><tbody>
      ${r.hits.map((h) => `<tr><td>${sevTag(h.severity)}</td><td><strong>${esc(h.name)}</strong> <span class="muted">${esc(h.category)}</span></td>
        <td class="num">${nf.format(h.count)}</td><td class="mono">${h.samples.map(esc).join("<br>")}</td>
        <td class="mono">${h.objects.slice(0, 5).map(esc).join("<br>")}${h.objects.length > 5 ? `<br><span class="muted">+${h.objects.length - 5} more</span>` : ""}</td></tr>`).join("")}
      </tbody></table></div></div>` : ""}
    ${r.risky_files.length ? `<div class="card"><h2>Risky files</h2><div class="table-wrap"><table>
      <thead><tr><th>Severity</th><th>Object</th><th>Why it matters</th></tr></thead><tbody>
      ${r.risky_files.slice(0, 100).map((f) => `<tr><td>${sevTag(f.severity)}</td><td class="mono">${esc(f.key)}</td><td class="secondary">${esc(f.reason)}</td></tr>`).join("")}
      </tbody></table></div></div>` : ""}`;
}

/* -- exposure test */
function renderVerifyTab(box, name, d) {
  box.innerHTML = `<div class="card"><h2>Exposure test</h2>
      <p class="secondary" style="margin-top:0">Requests this resource's public URLs <strong>without any credentials</strong>, exactly as an attacker would, to prove whether it can be listed or downloaded right now.
      Objects are only checked with HEAD requests; nothing is downloaded.</p>
      <button class="btn primary" data-action="verify" data-name="${esc(name)}">${d.proof ? "Test again" : "Test from the internet"}</button>
      <div id="ver-log" class="log" hidden></div></div>
    <div id="ver" class="stack" style="margin-top:16px">${d.proof ? proofHtml(d.proof) : ""}</div>`;
}

actions.verify = async (el) => {
  await withBusy(el, "Testing", async () => {
    try {
      const { job } = await api(`/api/clouds/${state.cloud}/resources/${enc(el.dataset.name)}/verify`, { method: "POST" });
      $("#ver").innerHTML = proofHtml(await runJob(job, logInto($("#ver-log"))));
      await refreshStatus();
    } catch (e) { toast(e.message, "err"); }
  });
};

function proofHtml(p) {
  const open = p.publicly_listable || p.publicly_readable;
  const names = p.results.flatMap((r) => r.sample);
  return `<div class="banner ${open ? "crit" : "good"}"><div class="icon">${open ? "!" : "✓"}</div><div><strong>${open ? "Publicly reachable" : "Not reachable anonymously"}</strong>${esc(p.summary)}
      <div class="muted" style="margin-top:4px">Tested ${esc(fmtDate(p.performed_at))}</div></div></div>
    <div class="card"><div class="table-wrap"><table><thead><tr><th>Check</th><th>Target</th><th>Result</th><th>Public</th></tr></thead><tbody>
      ${p.results.map((r) => `<tr><td>${r.check === "anonymous-list" ? "List contents" : "Download object"}</td><td class="mono">${esc(r.label)}</td>
        <td class="secondary">${esc(r.detail)}</td><td>${r.accessible ? badge("Yes", "crit") : badge("No", "good")}</td></tr>`).join("")}
    </tbody></table></div>
    ${names.length ? `<p class="secondary" style="margin:12px 0 0">Object names anyone can see: <span class="mono">${names.slice(0, 10).map(esc).join(", ")}</span></p>` : ""}</div>`;
}

/* -- investigation */
function renderInvestigateTab(box, name, d) {
  const days = recall("clouddetectx.days") || "30";
  box.innerHTML = `<div class="card"><div class="toolbar" style="margin:0">
      <label>Look back <input type="number" id="days" min="1" max="3650" value="${esc(days)}" style="width:90px"> days</label>
      <button class="btn primary" data-action="investigate" data-name="${esc(name)}">${d.investigation ? "Run again" : "Investigate access"}</button>
      <span class="muted">Reads access logs and audit logs. Read-only.</span></div>
      <div id="inv-progress" class="log" hidden></div></div>
    <div id="inv" class="stack" style="margin-top:16px">${d.investigation ? investigationHtml(d.investigation) : ""}</div>`;
}

actions.investigate = async (el) => {
  const days = $("#days").value;
  store("clouddetectx.days", days);
  await withBusy(el, "Investigating", async () => {
    try {
      const { job } = await api(`/api/clouds/${state.cloud}/resources/${enc(el.dataset.name)}/investigate`, { method: "POST", body: { days: Number(days) } });
      $("#inv").innerHTML = investigationHtml(await runJob(job, logInto($("#inv-progress"))));
      await refreshStatus();
    } catch (e) { toast(e.message, "err"); }
  });
};

function investigationHtml(inv) {
  const s = inv.summary;
  const v = VERDICT[inv.verdict];
  const external = new Set(s.external_ips);
  const untrusted = inv.access_events.filter((e) => ["anonymous", "-", ""].includes(e.principal || "") || external.has(e.source_ip));
  const metric = (val, label) => `<div class="metric"><div class="v">${val}</div><div class="l">${esc(label)}</div></div>`;
  return `
    <div class="banner ${v.cls}"><div class="icon">${v.icon}</div><div><strong>${esc(v.label)}</strong>${esc(inv.verdict_text)}</div></div>
    <div class="card"><h2>Summary</h2>
      <div class="metrics">
        ${metric(nf.format(s.total_events), "events analysed")}
        ${metric(nf.format(s.untrusted_requests), "requests from untrusted sources")}
        ${metric(nf.format(s.anonymous_requests), "anonymous requests")}
        ${metric(nf.format(s.objects_downloaded_by_untrusted.length), "objects downloaded by untrusted sources")}
        ${metric(esc(fmtBytes(s.bytes_downloaded_by_untrusted)), "downloaded by untrusted sources")}
        ${metric(nf.format(s.denied_requests_from_untrusted), "denied requests")}
      </div>
      <p class="muted" style="margin:12px 0 0">Log sources: ${inv.log_sources.length ? inv.log_sources.map(esc).join("; ") : "none"}</p>
      ${inv.notes.length ? `<ul class="plain" style="margin-top:8px">${inv.notes.map((n) => `<li class="secondary">${esc(n)}</li>`).join("")}</ul>` : ""}
    </div>
    ${inv.indicators.length ? `<div class="card"><h2>Indicators</h2><ul class="plain">${inv.indicators.map((i) =>
      `<li>${sevTag(i.severity)} <strong>${esc(i.title)}</strong> <span class="secondary">${esc(i.detail)}</span>
       ${i.mitre ? `<span class="chip" data-tip="MITRE ATT&CK: ${esc(i.mitre_name || "")}">ATT&amp;CK ${esc(i.mitre)}</span>` : ""}</li>`).join("")}</ul></div>` : ""}
    <div class="grid2">
      <div class="card"><h2>Objects downloaded by untrusted sources</h2>${s.objects_downloaded_by_untrusted.length
        ? `<ul class="plain mono">${s.objects_downloaded_by_untrusted.slice(0, 200).map((k) => `<li>${esc(k)}</li>`).join("")}</ul>` : `<p class="muted">None recorded.</p>`}</div>
      <div class="card"><h2>Top untrusted source IPs</h2>${s.top_untrusted_ips.length
        ? `<table><thead><tr><th>IP</th><th class="num">Requests</th></tr></thead><tbody>${s.top_untrusted_ips.map(([ip, n]) =>
          `<tr><td class="mono">${esc(ip)}</td><td class="num">${nf.format(n)}</td></tr>`).join("")}</tbody></table>` : `<p class="muted">None.</p>`}</div>
    </div>
    <div class="card"><h2>Configuration change history</h2>${inv.change_events.length ? `<div class="table-wrap"><table>
      <thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Source IP</th></tr></thead><tbody>${inv.change_events.slice(-50).reverse().map((c) =>
        `<tr><td class="nowrap">${esc(fmtDate(c.timestamp))}</td><td>${esc(c.action)}</td><td class="mono">${esc(c.actor || "-")}</td><td class="mono">${esc(c.source_ip || "-")}</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="muted">No configuration changes found in the audit log for this period.</p>`}</div>
    <div class="card"><h2>Untrusted access timeline</h2>${untrusted.length ? `<div class="table-wrap"><table>
      <thead><tr><th>Time</th><th>Operation</th><th>Object</th><th>Source IP</th><th>Principal</th><th class="num">Status</th></tr></thead><tbody>
      ${untrusted.slice(-200).reverse().map((e) => `<tr><td class="nowrap">${esc(fmtDate(e.timestamp))}</td><td>${esc(e.operation)}</td>
        <td class="mono">${esc(e.key || "-")}</td><td class="mono">${esc(e.source_ip || "-")}</td><td class="mono">${esc(e.principal || "-")}</td>
        <td class="num">${esc(e.status ?? "-")}</td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">No requests from untrusted sources.</p>`}</div>`;
}

/* -- remediation */
function renderRemediateTab(box, name, d) {
  box.innerHTML = `<div class="card">
      <h2>Remediation</h2>
      <p class="secondary" style="margin-top:0">The plan is built from the current configuration. Only public access is removed; every other permission is kept, and the original settings are saved in the incident report for rollback.</p>
      <div class="toolbar"><label class="check"><input type="checkbox" id="harden"> Also apply hardening (encryption, versioning, TLS where supported)</label></div>
      <button class="btn" data-action="plan" data-name="${esc(name)}">Preview plan</button>
      <div id="plan" style="margin-top:14px"></div>
    </div><div id="fix-result" style="margin-top:16px"></div>`;
  if (d.summary.status === "public") actions.plan($("[data-action=plan]"));
}

function actionsTable(list) {
  const cls = { applied: "good", planned: "neutral", skipped: "neutral", failed: "crit" };
  return `<div class="table-wrap"><table><thead><tr><th>Status</th><th>Action</th><th>Detail</th></tr></thead><tbody>${list.map((a) =>
    `<tr><td>${badge(a.status, cls[a.status] || "neutral")}</td><td>${esc(a.action)}</td><td class="secondary">${esc(a.detail)}</td></tr>`).join("")}</tbody></table></div>`;
}

actions.plan = async (el) => {
  const name = el.dataset.name;
  await withBusy(el, "Building plan", async () => {
    try {
      const { actions: plan } = await api(`/api/clouds/${state.cloud}/resources/${enc(name)}/plan`, { method: "POST", body: { harden: $("#harden").checked } });
      const changes = plan.filter((a) => a.status !== "skipped").length;
      $("#plan").innerHTML = actionsTable(plan) + (changes
        ? `<div style="margin-top:14px"><button class="btn danger" data-action="confirm-fix" data-name="${esc(name)}">Apply ${changes} change(s) to the live resource...</button></div>`
        : `<p class="muted">Nothing to change.</p>`);
    } catch (e) { toast(e.message, "err"); }
  });
};

actions["confirm-fix"] = (el) => {
  const name = el.dataset.name;
  const dlg = $("#dialog");
  dlg.innerHTML = `<form method="dialog"><div class="d-body">
      <h2>Apply remediation?</h2>
      <p class="secondary">This changes <strong>${esc(name)}</strong> in your live ${esc(cloudInfo().display)} account. Applications that rely on public access will lose it.</p>
      <label>Type <strong class="mono">${esc(name)}</strong> to confirm<input type="text" id="confirm-name" autocomplete="off" spellcheck="false"></label>
    </div><div class="d-foot"><button class="btn" value="cancel">Cancel</button>
      <button class="btn danger" id="do-fix" value="ok" disabled>Apply changes</button></div></form>`;
  const input = $("#confirm-name", dlg);
  input.addEventListener("input", () => { $("#do-fix", dlg).disabled = input.value.trim() !== name; });
  dlg.addEventListener("close", () => { if (dlg.returnValue === "ok") applyFix(name, input.value.trim()); }, { once: true });
  dlg.showModal();
  input.focus();
};

async function applyFix(name, confirmName) {
  const out = $("#fix-result");
  out.innerHTML = `<div class="card"><h2>${spinner} Applying remediation</h2><div class="log" id="fix-log">Starting...</div></div>`;
  try {
    const { job } = await api(`/api/clouds/${state.cloud}/resources/${enc(name)}/remediate`,
      { method: "POST", body: { harden: $("#harden").checked, confirm_name: confirmName } });
    const r = await runJob(job, logInto($("#fix-log")));
    const ok = !r.still_exposed && r.status === "CONTAINED";
    out.innerHTML = `<div class="banner ${ok ? "good" : "crit"}"><div class="icon">${ok ? "✓" : "!"}</div><div>
        <strong>${ok ? "Contained: no public exposure remains" : `Status: ${esc(r.status)}`}</strong>
        ${ok ? "A fresh scan confirmed the fix." : "Some actions failed or the resource is still exposed. Check the actions below."}
        <div style="margin-top:6px"><a href="#/reports/${enc(r.report_id)}">Open the incident report</a></div></div></div>
      <div class="card">${actionsTable(r.actions)}</div>`;
    $("#plan").innerHTML = "";
    await refreshStatus();
  } catch (e) {
    out.innerHTML = errorBox(e.message);
  }
}

/* ------------------------------------------------------------------ incident response */
async function renderRespond() {
  const c = cloudInfo();
  const head = `<div class="page-head"><div><h1>Incident response</h1>
    <div class="sub">${esc(c.display)} · for every exposed resource: prove the exposure, find what's inside, investigate access, then plan or apply the fix and write a report.</div></div></div>`;
  if (!c.scanned_at) {
    main.innerHTML = `${head}<div class="card empty"><h2>Scan first</h2><p>Incident response works on the results of the latest scan.</p>
      <button class="btn primary" data-action="scan">Scan ${esc(c.display)}</button><div id="scan-progress" class="log" hidden></div></div>`;
    return;
  }
  const { resources } = await api(`/api/clouds/${c.name}/resources`);
  const exposed = resources.filter((r) => r.status === "public").sort((a, b) => b.risk - a.risk);
  if (!exposed.length) {
    main.innerHTML = `${head}<div class="banner good"><div class="icon">✓</div><div><strong>No public exposure</strong>
      The latest scan (${esc(timeAgo(c.scanned_at))}) found nothing exposed in ${esc(c.display)}.</div></div>`;
    return;
  }
  main.innerHTML = `${head}<div class="card">
      <h2>1. Choose resources</h2>
      <ul class="plain">${exposed.map((r) => `<li><label class="check"><input type="checkbox" name="pick" value="${esc(r.name)}" checked>
        <strong>${esc(r.name)}</strong> ${riskCell(r.risk)} ${sevTag(r.top_severity)} <span class="muted">${esc(r.location || "")}</span></label></li>`).join("")}</ul>
    </div>
    <div class="card"><h2>2. Choose what to do</h2>
      <div class="stack">
        <label class="check"><input type="checkbox" id="r-verify" checked> Prove each exposure with anonymous requests from the internet</label>
        <label class="check"><input type="checkbox" id="r-discover" checked> Scan contents for secrets and personal data (reads a sample of objects; matches are redacted)</label>
        <label>Investigate access over the last <input type="number" id="r-days" min="1" max="3650" value="${esc(recall("clouddetectx.days") || "30")}" style="width:90px"> days</label>
        <hr class="sep">
        <label class="check"><input type="radio" name="mode" value="plan" checked> Save remediation plans only (changes nothing)</label>
        <label class="check"><input type="radio" name="mode" value="apply"> Remove public access from the selected resources</label>
        <label class="check"><input type="checkbox" id="r-harden"> Also apply hardening</label>
        <div id="apply-confirm" hidden><label>Type <strong class="mono">REMEDIATE</strong> to allow changes to live resources
          <input type="text" id="r-confirm" autocomplete="off" style="margin-left:8px"></label></div>
      </div>
      <div style="margin-top:16px"><button class="btn primary" data-action="respond" id="respond-btn">Start</button></div>
      <div id="r-log" class="log" hidden></div>
    </div><div id="r-result"></div>`;
  $$("input[name=mode]").forEach((r) => r.addEventListener("change", () => {
    const apply = $("input[name=mode]:checked").value === "apply";
    $("#apply-confirm").hidden = !apply;
    $("#respond-btn").className = `btn ${apply ? "danger" : "primary"}`;
  }));
}

actions.respond = async (el) => {
  const names = $$("input[name=pick]:checked").map((i) => i.value);
  if (!names.length) { toast("Select at least one resource", "err"); return; }
  await withBusy(el, "Working", async () => {
    try {
      const { job } = await api(`/api/clouds/${state.cloud}/respond`, { method: "POST", body: {
        names, mode: $("input[name=mode]:checked").value, harden: $("#r-harden").checked, verify: $("#r-verify").checked,
        discover: $("#r-discover").checked, days: Number($("#r-days").value), confirm: $("#r-confirm").value.trim() } });
      const results = await runJob(job, logInto($("#r-log")));
      $("#r-result").innerHTML = `<div class="card"><h2>Summary</h2><div class="table-wrap"><table>
        <thead><tr><th>Resource</th><th>Risk</th><th>Data</th><th>Access verdict</th><th>Outcome</th><th>Exposure now</th><th>Report</th></tr></thead><tbody>
        ${results.map((r) => `<tr><td><strong>${esc(r.name)}</strong></td><td>${riskCell(r.risk)}</td><td>${classBadge(r.classification)}</td>
          <td>${verdictBadge(r.verdict)}</td><td>${badge(r.outcome, INCIDENT_STATUS[r.outcome] || "neutral")}</td>
          <td>${statusBadge(r.still_exposed ? "public" : "private")}</td>
          <td><a href="#/reports/${enc(r.report_id)}">View</a></td></tr>`).join("")}</tbody></table></div></div>`;
      await refreshStatus();
    } catch (e) { toast(e.message, "err"); }
  });
};

/* ------------------------------------------------------------------ identity & access (IAM) */
const CAP_CLS = { admin: "crit", s3_full: "crit", can_expose: "warn", write_all: "warn", read_all: "" };

function findingCard(f, evidence = false) {
  const canWaive = f.waiver_resource && f.severity !== "INFO";
  return `<div class="finding ${f.exposes_data ? "exposing" : ""}">
    <div class="top">${sevTag(f.severity)}<span class="muted mono">${esc(f.check_id)}</span><span class="title">${esc(f.title)}</span>
      ${f.exposes_data ? badge("Public now", "crit") : ""}${f.evidence && f.evidence.account ? `<span class="chip">${esc(f.evidence.account)}</span>` : ""}
      ${canWaive ? `<button class="btn small link waive-btn" data-action="waive" data-resource="${esc(f.waiver_resource)}" data-check="${esc(f.check_id)}" data-title="${esc(f.title)}">Accept risk</button>` : ""}</div>
    <p>${esc(f.description)}</p>
    <div class="fix"><b>Fix:</b> ${esc(f.recommendation)}</div>
    ${f.controls && f.controls.length ? `<div class="chips">${f.controls.map(controlChip).join("")}</div>` : ""}
    ${evidence && f.evidence && Object.keys(f.evidence).length ? `<details><summary class="muted">Evidence</summary><pre class="json">${esc(JSON.stringify(f.evidence, null, 2))}</pre></details>` : ""}
  </div>`;
}

function drawPrincipals() {
  const q = state.iamQuery.trim().toLowerCase();
  const rows = state.principals.filter((p) => (state.iamFilter === "all" || (state.iamFilter === "flagged" ? p.risky : p.kind === state.iamFilter))
    && (!q || p.name.toLowerCase().includes(q)));
  $("#iam-rows").innerHTML = rows.length ? rows.map((p) => {
    const caps = p.capabilities.length ? p.capabilities.map((cap) => `<span class="chip ${CAP_CLS[cap.key]}" ${cap.level === "conditional" ? `data-tip="Only when a policy condition matches"` : ""}>${esc(cap.label)}${cap.level === "conditional" ? " ~" : ""}</span>`).join(" ")
      : `<span class="muted">scoped</span>`;
    const mfa = p.kind !== "user" ? `<span class="muted">-</span>` : !p.console ? `<span class="muted">no console</span>` : p.mfa ? badge("MFA", "good") : badge("No MFA", "crit");
    const keys = p.kind !== "user" ? `<span class="muted">-</span>` : p.keys.length
      ? p.keys.map((key) => `<span class="mono ${key.status === "Active" && key.age_days > 90 ? "stale" : ""}" data-tip="${esc(`${key.status}, created ${key.age_days} days ago`)}">…${esc(key.id_suffix)} ${key.age_days}d</span>`).join(" ")
      : `<span class="muted">none</span>`;
    return `<tr><td><strong>${esc(p.name)}</strong><div class="muted mono small">${esc(p.arn)}</div></td><td>${badge(p.kind, "neutral")}</td>
      <td><div class="chips tight">${caps}</div></td><td>${mfa}</td><td>${keys}</td>
      <td class="num" data-tip="${esc(p.policies.join(", ") || "none")}">${p.policies.length}</td></tr>`;
  }).join("") : `<tr><td colspan="6" class="muted">No principals match.</td></tr>`;
}

actions["iam-filter"] = (el) => {
  state.iamFilter = el.dataset.v;
  $$(".seg-ctrl button").forEach((b) => b.classList.toggle("on", b === el));
  drawPrincipals();
};
/* -- resource: access & encryption tab */
function renderAccessTab(box, name, d) {
  const a = d.access, e = a.encryption;
  const mark = (v) => (v === "yes" ? `<span class="acc yes" data-tip="Allowed">✓</span>`
    : v === "conditional" ? `<span class="acc cond" data-tip="Allowed only when a policy condition matches">~</span>` : `<span class="muted">–</span>`);
  const encCard = e ? `<div class="card"><h2>Encryption</h2><div class="metrics">
      <div class="metric"><div class="v">${esc(e.at_rest || "None")}</div><div class="l">at rest (default encryption)</div></div>
      <div class="metric"><div class="v">${e.in_transit_enforced ? "Required" : "Not enforced"}</div><div class="l">HTTPS in transit</div></div>
      <div class="metric"><div class="v">${e.kms_key ? esc(String(e.kms_key).split("/").pop()) : "-"}</div><div class="l">KMS key</div></div>
      <div class="metric"><div class="v">${e.bucket_key ? "On" : "Off"}</div><div class="l">S3 Bucket Key</div></div></div>
      ${!e.in_transit_enforced ? `<p class="muted" style="margin:12px 0 0">Requests over plain HTTP are allowed. Remediation with <strong>hardening</strong> adds a statement that denies them.</p>` : ""}</div>`
    : `<div class="card"><h2>Encryption</h2><p class="muted">Encryption details are shown for AWS S3. Azure Storage and Cloud Storage always encrypt data at rest; their in-transit settings appear in Findings.</p></div>`;
  let who;
  if (!a.iam_supported) who = `<p class="muted">IAM permission analysis is available for AWS.</p>`;
  else if (!a.iam_analyzed) who = `<p class="muted">${esc(a.iam_error || "IAM permissions are analysed with every full scan.")}</p>`;
  else if (!a.principals.length) who = `<p class="muted">No IAM user or role in this account is granted access to this bucket by an identity policy.</p>`;
  else {
    who = `<div class="table-wrap"><table><thead><tr><th>Principal</th><th>Type</th><th class="c">Read</th><th class="c">List</th><th class="c">Write / delete</th><th class="c" data-tip="Can change the bucket policy, ACLs or Block Public Access">Change access</th><th>Granted by</th></tr></thead><tbody>
      ${a.principals.map((p) => `<tr><td><strong>${esc(p.name)}</strong>${p.admin ? ` <span class="chip crit">admin</span>` : ""}</td><td>${badge(p.kind, "neutral")}</td>
        <td class="c">${mark(p.read)}</td><td class="c">${mark(p.list)}</td><td class="c">${mark(p.write)}</td><td class="c">${mark(p.manage)}</td>
        <td class="secondary small">${esc(p.via.slice(0, 3).join(", "))}${p.via.length > 3 ? ` +${p.via.length - 3}` : ""}</td></tr>`).join("")}</tbody></table></div>`;
  }
  box.innerHTML = `<div class="stack">
    ${a.public ? `<div class="banner crit"><div class="icon">!</div><div><strong>Anyone on the internet can access this ${esc(d.summary.kind)}</strong>See Findings for the public ACL or policy, and Remediation to close it.</div></div>` : ""}
    ${encCard}
    ${a.external_accounts.length ? `<div class="card"><h2>Other AWS accounts with access</h2><table><thead><tr><th>Account</th><th>Actions</th><th>Statement</th></tr></thead><tbody>
      ${a.external_accounts.map((st) => `<tr><td class="mono">${st.accounts.map(esc).join(", ")}</td><td class="mono small">${st.actions.map(esc).join(", ")}</td><td>${esc(st.sid || "-")}</td></tr>`).join("")}</tbody></table></div>` : ""}
    <div class="card"><div class="card-head"><h2>Who in this account can access it</h2>${a.iam_analyzed ? `<a class="small-link" href="#/iam">All principals</a>` : ""}</div>${who}
      ${a.iam_analyzed && a.principals.length ? `<p class="muted small" style="margin:10px 0 0">From identity policies (inline, managed and group). Explicit denies are applied; permission boundaries and SCPs are not evaluated.</p>` : ""}</div>
  </div>`;
}

/* ------------------------------------------------------------------ compliance */
async function renderCompliance() {
  const c = cloudInfo();
  const head = `<div class="page-head"><div><h1>Compliance</h1>
    <div class="sub">${esc(c.display)} · controls assessed by the latest scan${c.name === "aws" ? " and IAM analysis" : ""}. Use this as evidence input for audits, not as a certification.</div></div>
    ${c.scanned_at ? `<div class="actions"><button class="btn primary" data-action="compliance-report">Generate compliance report</button></div>` : ""}</div>`;
  if (!c.scanned_at) {
    main.innerHTML = `${head}<div class="card empty"><h2>Scan first</h2><p>Compliance mapping is built from scan findings.</p>
      <button class="btn primary" data-action="scan">Scan ${esc(c.display)}</button><div id="scan-progress" class="log" hidden></div></div>`;
    return;
  }
  const data = await api(`/api/clouds/${c.name}/compliance`);
  const fws = Object.entries(data.frameworks);
  const tile = ([k, v]) => {
    const st = data.status[k];
    const pct = st.pass_rate ?? 0;
    return `<div class="kpi"><div class="label">${esc(v)}</div><div class="value"><span data-count="${pct}">${pct}</span><span class="unit">% of checks pass</span></div>
      <div class="meter big ${rateClass(pct)}" style="margin-top:8px"><i style="width:${Math.max(2, pct)}%"></i></div>
      <div class="note">${st.passing} of ${st.assessed} controls pass on every resource${st.failing ? ` · <span class="nowrap" style="color:var(--critical)">${st.failing} failing</span>` : ""}</div></div>`;
  };
  main.innerHTML = `${head}<section class="kpis fw">${fws.map(tile).join("")}</section>
    <section class="card" style="margin-top:16px"><div class="toolbar"><div class="seg-ctrl" role="group" aria-label="Framework">
      ${[["all", "All"], ...fws].map(([k, v]) => `<button data-action="fw" data-fw="${k}" class="${state.fw === k ? "on" : ""}">${esc(k === "all" ? "All" : FW_SHORT[k])}</button>`).join("")}
      </div><span class="muted">${data.resources} resource(s) assessed</span></div>
      <div class="table-wrap"><table><thead><tr><th>Framework</th><th>Control</th><th>Title</th><th>Worst</th><th>Resources</th><th>Checks</th></tr></thead>
      <tbody id="fw-rows"></tbody></table></div></section>`;
  state.controls = data.controls;
  drawControls();
  animateIn();
}

function drawControls() {
  const rows = state.controls.filter((r) => state.fw === "all" || r.framework === state.fw);
  $("#fw-rows").innerHTML = rows.length ? rows.map((r) => `<tr><td class="nowrap">${esc(FW_SHORT[r.framework])}</td><td class="mono nowrap">${esc(r.id)}</td>
    <td>${esc(r.title)}</td><td>${sevTag(r.worst)}</td>
    <td>${r.resources.slice(0, 4).map((n) => (n === "IAM (account)" ? `<a href="#/iam">${esc(n)}</a>` : `<a href="#/r/${state.cloud}/${enc(n)}">${esc(n)}</a>`)).join(", ")}${r.resources.length > 4 ? ` <span class="muted">+${r.resources.length - 4}</span>` : ""}</td>
    <td class="mono muted">${r.checks.map(esc).join(", ")}</td></tr>`).join("")
    : `<tr><td colspan="6" class="muted">No failing controls for this framework.</td></tr>`;
}
actions.fw = (el) => {
  state.fw = el.dataset.fw;
  $$(".seg-ctrl button").forEach((b) => b.classList.toggle("on", b === el));
  drawControls();
};

/* ------------------------------------------------------------------ history */
async function renderHistory() {
  const c = cloudInfo();
  const { scans, drift } = await api(`/api/clouds/${c.name}/history`);
  const last = scans[scans.length - 1];
  main.innerHTML = `<div class="page-head"><div><h1>History</h1>
      <div class="sub">${esc(c.display)} · every full scan is recorded locally for drift detection and trends.</div></div>
      <div class="actions"><button class="btn primary" data-action="scan">Scan now</button></div></div>
    <div id="scan-progress" class="log" hidden></div>
    ${drift ? `<div class="stack">${driftBanner({ drift, alert_error: null })}</div>` : ""}
    <section class="grid2">
      <div class="card"><h2>Publicly exposed resources</h2>${lineChart(scans.map((s) => ({ t: s.scanned_at, v: s.public })), { label: "public", cls: "crit-line" })}</div>
      <div class="card"><h2>Security score</h2>${lineChart(scans.filter((s) => s.posture_score != null).map((s) => ({ t: s.scanned_at, v: s.posture_score })), { label: "score", max: 100 })}</div>
    </section>
    <section class="card" style="margin-top:16px"><h2>Scans</h2>${scans.length ? `<div class="table-wrap"><table>
      <thead><tr><th>Scanned</th><th>Account</th><th class="num">Resources</th><th class="num">Public</th><th class="num">Mitigated</th><th class="num" data-tip="Score recorded at scan time; the dashboard score also reflects discovery, exposure tests and investigations run since.">Score at scan</th></tr></thead><tbody>
      ${scans.slice().reverse().map((s) => `<tr><td class="nowrap">${esc(fmtDate(s.scanned_at))}</td><td class="secondary">${esc(s.account)}</td>
        <td class="num">${s.resources}</td><td class="num">${s.public ? `<strong style="color:var(--critical)">${s.public}</strong>` : 0}</td>
        <td class="num">${s.mitigated}</td><td class="num">${s.posture_score ?? "-"}</td></tr>`).join("")}</tbody></table></div>`
      : `<p class="muted">No scans recorded yet.</p>`}
      ${last ? `<p class="muted" style="margin:10px 0 0">Stored in the data folder (Settings &gt; General). For continuous monitoring run <span class="mono">python main.py -p ${esc(c.name)} watch --every 60</span>.</p>` : ""}</section>`;
  bindLineCharts();
}

/* ------------------------------------------------------------------ reports */
async function renderReports() {
  const { folder, reports } = await api("/api/reports");
  const when = (v) => (v && v.includes("UTC") ? v.replace(" UTC", "Z").replace(" ", "T") : v);
  main.innerHTML = `<div class="page-head"><div><h1>Reports</h1><div class="sub mono">${esc(folder)}</div></div>
      <div class="actions"><button class="btn" data-action="compliance-report">New compliance report</button></div></div>
    <div class="card">${reports.length ? `<div class="table-wrap"><table>
      <thead><tr><th>Date</th><th>Type</th><th>Subject</th><th>Cloud</th><th>Severity / grade</th><th>Status</th><th>Access verdict</th></tr></thead><tbody>
      ${reports.map((r) => r.type === "compliance" ? `<tr class="clickable" data-action="open-report" data-id="${esc(r.id)}" tabindex="0">
        <td class="nowrap">${esc(fmtDate(when(r.detected_at)))}</td><td>${badge("Compliance", "neutral")}</td><td><strong>${esc(r.resource)}</strong></td>
        <td>${esc((r.provider || "").toUpperCase())}</td><td>${r.grade ? `<strong>Grade ${esc(r.grade)}</strong>` : "-"}</td>
        <td>${r.controls_assessed ? `${r.controls_assessed - r.controls_failing} of ${r.controls_assessed} controls pass` : "-"}</td><td><span class="muted">-</span></td></tr>`
        : `<tr class="clickable" data-action="open-report" data-id="${esc(r.id)}" tabindex="0">
        <td class="nowrap">${esc(fmtDate(r.detected_at))}</td><td>${badge("Incident", "neutral")}</td><td><strong>${esc(r.resource)}</strong></td>
        <td>${esc((r.provider || "").toUpperCase())}</td><td>${sevTag(r.severity)}</td>
        <td>${badge(r.status || "-", INCIDENT_STATUS[r.status] || "neutral")}</td><td>${verdictBadge(r.verdict)}</td></tr>`).join("")}
      </tbody></table></div>` : `<div class="empty"><h2>No reports yet</h2><p>Incident reports are written when you investigate, remediate or respond. Compliance reports are generated from the Compliance page.</p></div>`}</div>`;
}
actions["open-report"] = (el) => { location.hash = `#/reports/${enc(el.dataset.id)}`; };

/* ------------------------------------------------------------------ settings */
const LIST_KINDS = new Set(["region", "profile", "subscription", "project", "bucket"]);

async function renderSettings() {
  const [data, sched, wv] = await Promise.all([api("/api/settings"), api("/api/schedule").catch(() => ({ installed: false, detail: "" })),
    api("/api/waivers")]);
  const plain = data.sections.flatMap((sec) => sec.fields).filter((f) => f.secret && f.stored_in === ".env");
  main.innerHTML = `<div class="page-head"><div><h1>Settings</h1>
      <div class="sub">Saved to <span class="mono">${esc(data.env_file)}</span>. Secrets go to ${data.keychain ? "your OS keychain" : ".env (no OS keychain available)"}; cloud credentials stay in each cloud's own store.</div></div>
      <div class="actions"><a class="btn" href="#/setup">Run setup wizard</a></div></div>
    ${state.status.warnings.map((w) => `<div class="banner warn" style="margin-bottom:12px"><div class="icon">!</div><div>${esc(w)}</div></div>`).join("")}
    ${plain.length && data.keychain ? `<div class="banner warn" style="margin-bottom:12px"><div class="icon">!</div><div><strong>${plain.length} secret(s) are stored in plain text in .env</strong>
      ${plain.map((f) => esc(f.label)).join(", ")}. <button class="btn small" data-action="migrate-secrets">Move to OS keychain</button></div></div>` : ""}
    <div class="stack">${data.sections.map(sectionHtml).join("")}${scheduleCard(sched)}${waiversCard(wv.waivers)}</div>`;
  $$(".form-row").forEach(bindField);
  $$("input[list]").forEach((input) => { if (["region", "profile"].includes(input.dataset.kind)) loadOptions(input); });
  bindGcpUpload();
  const target = location.hash.split("/")[2];
  if (target) { const el = document.getElementById(`sec-${target}`); if (el) el.scrollIntoView(); }
}

function sectionHtml(sec) {
  const p = sec.provider;
  const signin = {
    aws: `<span class="muted">Sign in:</span>
      <button class="btn small" data-action="signin" data-cloud="aws" data-method="sso">AWS SSO login (uses the profile above)</button>
      <button class="btn small" data-action="aws-keys">Add an access-key profile</button>`,
    azure: `<span class="muted">Sign in:</span>
      <button class="btn small" data-action="signin" data-cloud="azure" data-method="cli">az login (browser)</button>
      <button class="btn small" data-action="signin" data-cloud="azure" data-method="device">az login with device code</button>
      <span class="muted">or fill in the service principal fields above</span>`,
    gcp: `<span class="muted">Sign in:</span>
      <button class="btn small" data-action="signin" data-cloud="gcp" data-method="cli">gcloud application-default login</button>
      <button class="btn small" data-action="gcp-key">Upload service-account key…</button>
      <input type="file" id="gcp-key-file" accept=".json,application/json" hidden>
      <span class="muted">The key is saved in the data folder and used as GOOGLE_APPLICATION_CREDENTIALS.</span>`,
  };
  const c = p ? cloudInfo(p) : null;
  const extra = sec.name === "Alerts"
    ? `<div class="signin"><button class="btn small" data-action="test-alert">Send a test alert</button>
       <span class="muted">Alerts fire on new public exposures at or above the threshold, and whenever an investigation confirms data access.</span></div>` : "";
  return `<section class="card" id="sec-${esc(sec.name)}"><div class="card-head"><h2>${esc(sec.title)}</h2>
      ${p ? `<div class="toolbar" style="margin:0"><span id="conn-${p}">${c.connected ? badge("Connected", "good") : c.error ? badge("Error", "crit") : badge("Not connected", "neutral")}</span>
        <button class="btn small" data-action="test" data-cloud="${p}">Test connection</button></div>` : ""}</div>
    ${sec.fields.map(fieldHtml).join("")}
    ${p ? `<div class="signin">${signin[p]}</div><div id="aux-${p}"></div>` : ""}${extra}</section>`;
}

function fieldHtml(f) {
  let ctrl;
  if (f.kind === "providers") {
    const on = new Set(f.value.split(",").filter(Boolean));
    ctrl = ["aws", "azure", "gcp"].map((p) => `<label class="check"><input type="checkbox" value="${p}" ${on.has(p) ? "checked" : ""}> ${p.toUpperCase()}</label>`).join("");
  } else if (f.kind === "bool") {
    ctrl = `<select>${["on", "off"].map((v) => `<option value="${v}" ${(f.value || f.default) === v ? "selected" : ""}>${v === "on" ? "On" : "Off"}</option>`).join("")}</select>`;
  } else if (f.kind === "int") {
    ctrl = `<input type="number" min="${f.min}" max="${f.max}" value="${esc(f.value || f.default)}">`;
  } else if (f.secret) {
    ctrl = `<input type="password" autocomplete="new-password" placeholder="${f.is_set ? "set (hidden) - type to replace" : "not set"}">
      ${f.is_set ? `<button class="btn small" data-action="clear-field">Clear</button>` : ""}`;
  } else {
    const list = LIST_KINDS.has(f.kind) ? `list="dl-${esc(f.key)}" data-kind="${esc(f.kind)}"` : "";
    ctrl = `<input type="text" ${list} value="${esc(f.value)}" placeholder="${esc(f.default ? `default: ${f.default}` : "not set")}" spellcheck="false">
      ${LIST_KINDS.has(f.kind) ? `<datalist id="dl-${esc(f.key)}"></datalist>
        ${["subscription", "project", "bucket"].includes(f.kind) ? `<button class="btn small" data-action="load-options">Load list</button>` : ""}` : ""}`;
  }
  return `<div class="form-row" data-key="${esc(f.key)}" data-kind="${esc(f.kind)}" data-secret="${f.secret ? 1 : ""}">
    <div><strong>${esc(f.label)}</strong><div class="help">${esc(f.help)}</div></div>
    <div class="ctrl">${ctrl}<button class="btn small primary" data-action="save-field" hidden>Save</button></div>
    <div class="state" aria-live="polite">${f.stored_in ? (f.stored_in === "keychain" ? "in OS keychain" : "in .env") : f.is_set ? "" : f.default ? "default" : "not set"}</div></div>`;
}

function fieldValue(row) {
  if (row.dataset.kind === "providers") return $$("input[type=checkbox]:checked", row).map((i) => i.value).join(",");
  if (row.dataset.kind === "bool") return $("select", row).value;
  return $("input", row).value;
}

function bindField(row) {
  const saveBtn = $("[data-action=save-field]", row);
  const initial = fieldValue(row);
  const onChange = () => { saveBtn.hidden = row.dataset.secret ? !fieldValue(row) : fieldValue(row) === initial; };
  $$("input, select", row).forEach((i) => { i.addEventListener("input", onChange); i.addEventListener("change", onChange); });
  $$("input[type=text], input[type=number], input[type=password]", row).forEach((i) =>
    i.addEventListener("keydown", (e) => { if (e.key === "Enter" && !saveBtn.hidden) saveField(row, saveBtn); }));
}

async function saveField(row, btn, value = fieldValue(row)) {
  const st = $(".state", row);
  await withBusy(btn, "Saving", async () => {
    try {
      const f = await api(`/api/settings/${enc(row.dataset.key)}`, { method: "PUT", body: { value } });
      st.textContent = f.stored_in === "keychain" ? "saved to OS keychain" : "saved";
      st.className = "state saved";
      if (row.dataset.secret) { $("input", row).value = ""; $("input", row).placeholder = f.is_set ? "set (hidden) - type to replace" : "not set"; }
      btn.hidden = true;
      await refreshStatus();
    } catch (e) {
      st.textContent = "";
      toast(e.message, "err");
    }
  });
}

actions["save-field"] = (el) => saveField(el.closest(".form-row"), el);
actions["clear-field"] = (el) => saveField(el.closest(".form-row"), el, "");

async function loadOptions(input, btn) {
  const dl = document.getElementById(input.getAttribute("list"));
  await withBusy(btn, "Loading", async () => {
    try {
      const r = await api(`/api/settings/options/${input.dataset.kind}`);
      dl.innerHTML = r.options.map((o) => `<option value="${esc(o.value)}">${esc(o.label)}</option>`).join("");
      if (r.note) toast(r.note);
      else if (btn) toast(`${r.options.length} option(s) loaded: click the field to choose`, "ok");
    } catch (e) { if (btn) toast(e.message, "err"); }
  });
}
actions["load-options"] = (el) => loadOptions($("input[list]", el.closest(".form-row")), el);

actions["test-alert"] = async (el) => {
  await withBusy(el, "Sending", async () => {
    try { await api("/api/alerts/test", { method: "POST" }); toast("Test alert sent", "ok"); } catch (e) { toast(e.message, "err"); }
  });
};

actions.test = async (el) => {
  const cloud = el.dataset.cloud;
  await withBusy(el, "Testing", async () => {
    try {
      const c = await api(`/api/clouds/${cloud}/connect`, { method: "POST" });
      $(`#conn-${cloud}`).innerHTML = badge("Connected", "good");
      toast(c.account, "ok");
    } catch (e) {
      $(`#conn-${cloud}`).innerHTML = badge("Error", "crit");
      toast(e.message, "err");
    }
    await refreshStatus();
  });
};

actions.signin = async (el) => {
  const cloud = el.dataset.cloud;
  await withBusy(el, "Waiting for sign-in", async () => {
    try {
      const { job } = await api(`/api/clouds/${cloud}/signin`, { method: "POST", body: { method: el.dataset.method } });
      toast("Finish signing in in the browser window that opened (device codes appear in the dashboard's terminal).");
      await runJob(job);
      toast("Signed in. Testing connection...", "ok");
      actions.test($(`[data-action=test][data-cloud=${cloud}]`));
    } catch (e) { toast(e.message, "err"); }
  });
};

actions["aws-keys"] = () => {
  const box = $("#aux-aws");
  if (box.innerHTML) { box.innerHTML = ""; return; }
  box.innerHTML = `<div class="subform">
      <label>Profile name<input type="text" id="k-name" value="clouddetectx" spellcheck="false"></label>
      <label>Access key ID<input type="text" id="k-id" autocomplete="off" spellcheck="false"></label>
      <label>Secret access key<input type="password" id="k-secret" autocomplete="new-password"></label>
      <label>Region<input type="text" id="k-region" list="dl-AWS_REGION" value="us-east-1" spellcheck="false"></label>
    </div><p class="muted" style="margin:8px 0">Written to ~/.aws/credentials exactly like <span class="mono">aws configure</span>, never to .env. Prefer SSO or short-lived credentials where you can.</p>
    <button class="btn primary small" data-action="save-keys">Save profile and use it</button>`;
};
actions["save-keys"] = async (el) => {
  await withBusy(el, "Saving", async () => {
    try {
      const r = await api("/api/settings/aws-profile", { method: "POST", body: {
        name: $("#k-name").value, key_id: $("#k-id").value, secret: $("#k-secret").value, region: $("#k-region").value } });
      toast(`Profile '${r.profile}' saved`, "ok");
      await refreshStatus();
      await renderSettings();
      actions.test($("[data-action=test][data-cloud=aws]"));
    } catch (e) { toast(e.message, "err"); }
  });
};

/* ------------------------------------------------------------------ boot */
route();

/* ------------------------------------------------------------------ exports, waivers */
function exportMenu(cloud) {
  return `<details class="menu"><summary class="btn">Export</summary><div class="menu-list" role="menu">
    <a role="menuitem" href="/api/clouds/${enc(cloud)}/export/sarif">SARIF <span class="muted">code scanning</span></a>
    <a role="menuitem" href="/api/clouds/${enc(cloud)}/export/ocsf">OCSF JSON <span class="muted">SIEM</span></a>
    <a role="menuitem" href="/api/clouds/${enc(cloud)}/export/csv">CSV <span class="muted">spreadsheet</span></a>
    <a role="menuitem" href="#" data-action="compliance-report">Compliance report <span class="muted">PDF / Markdown</span></a></div></details>`;
}

function acceptedList(list) {
  if (!list || !list.length) return "";
  return `<section class="card" style="margin-top:16px"><div class="card-head"><h2>Accepted risks (${list.length})</h2>
      <a class="small-link" href="#/settings/waivers">All waivers</a></div>
    <p class="muted" style="margin-top:0">These findings are covered by a waiver: they still show here but don't count towards risk, scores, compliance, alerts or exit codes until the waiver expires.</p>
    <div class="table-wrap"><table><thead><tr><th>Check</th><th>Finding</th><th>Reason</th><th>Expires</th><th></th></tr></thead><tbody>
    ${list.map((f) => `<tr><td class="mono nowrap">${esc(f.check_id)}</td><td>${sevTag(f.severity)} ${esc(f.title)}</td>
      <td>${esc(f.waiver.reason)}${f.waiver.check_id === "*" ? ` <span class="chip">all checks</span>` : ""}</td>
      <td class="nowrap">${esc(f.waiver.expires)}</td>
      <td><button class="btn small" data-action="unwaive" data-id="${esc(f.waiver.id)}">Remove</button></td></tr>`).join("")}
    </tbody></table></div></section>`;
}

function isoIn(days) {
  const d = new Date(Date.now() + days * 86400000);
  return d.toISOString().slice(0, 10);
}

actions.waive = (el) => {
  const dlg = $("#dialog");
  const { resource, check, title } = el.dataset;
  dlg.innerHTML = `<form method="dialog"><div class="d-body">
      <h2>Accept this risk?</h2>
      <p class="secondary" style="margin-top:0">For things that are intended, like a public website bucket. The finding stays visible but stops counting towards scores, compliance and alerts until the expiry date.</p>
      <p><strong>${esc(check)}</strong> ${esc(title)}<br><span class="muted mono">${esc(resource)}</span></p>
      <label class="check"><input type="radio" name="w-scope" value="${esc(check)}" checked> Only this check</label><br>
      <label class="check"><input type="radio" name="w-scope" value="*"> Every check on ${esc(resource)}</label>
      <label style="display:block;margin-top:12px">Reason<input type="text" id="w-reason" maxlength="500" placeholder="e.g. public website assets, reviewed by security" autocomplete="off"></label>
      <label style="display:block;margin-top:10px">Valid until<input type="date" id="w-expires" value="${isoIn(90)}" min="${isoIn(0)}" max="${isoIn(730)}"></label>
    </div><div class="d-foot"><button class="btn" value="cancel">Cancel</button>
      <button class="btn primary" id="w-ok" value="ok" disabled>Accept risk</button></div></form>`;
  const reason = $("#w-reason", dlg);
  reason.addEventListener("input", () => { $("#w-ok", dlg).disabled = reason.value.trim().length < 5; });
  dlg.addEventListener("close", async () => {
    if (dlg.returnValue !== "ok") return;
    try {
      await api("/api/waivers", { method: "POST", body: { provider: state.cloud, resource, check_id: $("input[name=w-scope]:checked", dlg).value,
        reason: reason.value.trim(), expires: $("#w-expires", dlg).value } });
      toast("Risk accepted", "ok");
      await refreshStatus();
      route();
    } catch (e) { toast(e.message, "err"); }
  }, { once: true });
  dlg.showModal();
  reason.focus();
};

actions.unwaive = async (el) => {
  try {
    await api(`/api/waivers/${enc(el.dataset.id)}`, { method: "DELETE" });
    toast("Waiver removed", "ok");
    await refreshStatus();
    route();
  } catch (e) { toast(e.message, "err"); }
};

/* ------------------------------------------------------------------ account & IAM page */
async function renderIam() {
  const c = cloudInfo();
  const head = `<div class="page-head"><div><h1>Account &amp; IAM</h1>
      <div class="sub">${esc(c.display)} · who can reach your storage, plus account-wide checks: audit logging, root/owner security, network exposure, public databases and snapshots, key rotation.</div></div>
      <div class="actions">${c.connected || c.scanned_at ? `<button class="btn" data-action="iam-analyze">Re-run account checks</button>` : ""}</div></div>
    <div id="iam-log" class="log" hidden></div>`;
  const data = await api(`/api/clouds/${c.name}/account`);
  if (!data.report) {
    main.innerHTML = `${head}<div class="card empty"><h2>${data.enabled ? "Not checked yet" : "Account-wide checks are off"}</h2>
      <p>${data.enabled ? "Account-wide checks run with every scan. They are read-only and use the same permissions as the scan (SecurityAudit / Reader / Security Reviewer)."
        : "Turn on 'Account-wide checks' in Settings > General."}</p>
      ${data.enabled ? `<button class="btn primary" data-action="scan">Scan now</button><div id="scan-progress" class="log" hidden></div>` : `<a class="btn" href="#/settings">Settings</a>`}</div>`;
    return;
  }
  const r = data.report;
  const k = r.iam ? r.iam.counts : null;
  const sev = (s) => r.findings.filter((f) => f.severity === s).length;
  const tile = (label, value, note, cls = "") => `<div class="kpi ${cls}"><div class="label">${esc(label)}</div>
    <div class="value"><span data-count="${value}">${nf.format(value)}</span></div><div class="note">${note}</div></div>`;
  const errors = Object.entries(r.errors || {});
  main.innerHTML = `${head}
    ${errors.length ? `<div class="banner warn" style="margin-bottom:16px"><div class="icon">!</div><div><strong>${errors.length} area(s) could not be checked</strong>
      ${errors.slice(0, 6).map(([a, e]) => `${esc(a)}: <span class="muted">${esc(String(e).slice(0, 140))}</span>`).join("<br>")}</div></div>` : ""}
    <section class="kpis iam">
      ${tile("Account-wide findings", r.findings.length, `${sev("CRITICAL")} critical · ${sev("HIGH")} high · ${sev("MEDIUM")} medium`, r.findings.some((f) => ["CRITICAL", "HIGH"].includes(f.severity)) ? "hero alert" : "hero")}
      ${k ? tile("Principals analysed", k.principals, `${nf.format(k.users)} users · ${nf.format(k.roles)} roles/other`) : tile("Accepted risks", r.waived.length, "covered by waivers")}
      ${k ? tile("Flagged principals", k.risky, k.risky ? badge("Review needed", "crit") : badge("Nothing flagged", "good")) : ""}
      ${k ? tile("Admin or full storage access", k.admin + k.s3_full, `${nf.format(k.admin)} administrator(s) · ${nf.format(k.s3_full)} with full storage access`) : ""}
      ${k ? tile("Can make buckets public", k.can_expose, "change policies, ACLs or public access settings") : ""}
      ${k ? tile("Stale credentials", k.no_mfa + k.old_keys, `${nf.format(k.no_mfa)} console user(s) without MFA · ${nf.format(k.old_keys)} key(s) over 90 days`) : ""}
    </section>
    <section style="margin-top:16px"><h2>Findings</h2>
      ${r.findings.length ? r.findings.map((f) => findingCard(f, true)).join("") : `<div class="card empty"><h2>No account-wide findings</h2><p>Every account-wide check passed.</p></div>`}</section>
    ${acceptedList(r.waived)}
    ${r.iam ? `<section class="card" style="margin-top:16px"><div class="card-head"><h2>Principals</h2></div>
      <div class="toolbar">
        <input type="search" id="iam-q" placeholder="Filter by name" value="${esc(state.iamQuery)}" aria-label="Filter principals">
        <div class="seg-ctrl" role="group" aria-label="Principal filter">
          ${[["flagged", `Flagged (${k.risky})`], ["all", `All (${k.principals})`], ["user", "Users"], ["role", "Roles"]].map(([v, l]) =>
            `<button data-action="iam-filter" data-v="${v}" class="${state.iamFilter === v ? "on" : ""}">${esc(l)}</button>`).join("")}
        </div></div>
      <div class="table-wrap"><table><thead><tr><th>Principal</th><th>Type</th><th>Storage permissions</th><th>Console MFA</th><th>Keys</th><th class="num">Policies</th></tr></thead>
        <tbody id="iam-rows"></tbody></table></div></section>` : ""}
    <p class="muted small" style="margin-top:12px">${r.notes.map(esc).join("<br>")}</p>`;
  if (r.iam) {
    state.principals = r.iam.principals;
    drawPrincipals();
    $("#iam-q").addEventListener("input", (e) => { state.iamQuery = e.target.value; drawPrincipals(); });
  }
  animateIn();
}

actions["iam-analyze"] = async (el) => {
  await withBusy(el, "Checking", async () => {
    try {
      const { job } = await api(`/api/clouds/${state.cloud}/account/analyze`, { method: "POST" });
      await runJob(job, logInto($("#iam-log")));
      toast("Account checks complete", "ok");
      route();
    } catch (e) { toast(e.message, "err"); }
  });
};

/* ------------------------------------------------------------------ report page: PDF + rollback */
async function renderReport(id) {
  const r = await api(`/api/reports/${enc(id)}`);
  const rb = r.rollback;
  main.innerHTML = `<a class="crumb" href="#/reports">&larr; Reports</a>
    <div class="page-head"><div><h1 class="mono" style="font-size:16px">${esc(id)}</h1></div><div class="actions">
      <a class="btn" href="/api/reports/${enc(id)}/download/pdf">Download PDF</a>
      <a class="btn" href="/api/reports/${enc(id)}/download/md">Markdown</a>
      <a class="btn" href="/api/reports/${enc(id)}/download/json">Evidence JSON</a>
      ${r.can_rollback ? `<button class="btn danger" data-action="rollback" data-id="${esc(id)}" data-name="${esc(r.resource)}">Roll back…</button>` : ""}</div></div>
    ${rb ? `<div class="banner ${rb.status === "applied" ? "warn" : "crit"}" style="margin-bottom:16px"><div class="icon">↺</div><div>
      <strong>Rolled back ${esc(timeAgo(rb.at))} (${esc(rb.status)})</strong>The configuration from before remediation was restored.</div></div>` : ""}
    <div id="rollback-box"></div>
    <div class="card report">${r.html}</div>`;
}

actions.rollback = async (el) => {
  const { id, name } = el.dataset;
  const box = $("#rollback-box");
  let plan;
  try {
    plan = await api(`/api/reports/${enc(id)}/rollback`, { method: "POST", body: { dry_run: true } });
  } catch (e) { toast(e.message, "err"); return; }
  const dlg = $("#dialog");
  dlg.innerHTML = `<form method="dialog"><div class="d-body">
      <h2>Roll back remediation?</h2>
      <p class="secondary" style="margin-top:0">This restores the configuration saved before remediation on <strong>${esc(name)}</strong>.
        <strong>If it was public, it becomes public again.</strong></p>
      ${actionsTable(plan.actions)}
      <label style="display:block;margin-top:12px">Type <strong class="mono">${esc(name)}</strong> to confirm<input type="text" id="rb-name" autocomplete="off" spellcheck="false"></label>
    </div><div class="d-foot"><button class="btn" value="cancel">Cancel</button>
      <button class="btn danger" id="rb-ok" value="ok" disabled>Roll back</button></div></form>`;
  const input = $("#rb-name", dlg);
  input.addEventListener("input", () => { $("#rb-ok", dlg).disabled = input.value.trim() !== name; });
  dlg.addEventListener("close", async () => {
    if (dlg.returnValue !== "ok") return;
    try {
      const res = await api(`/api/reports/${enc(id)}/rollback`, { method: "POST", body: { confirm_name: input.value.trim() } });
      box.innerHTML = `<div class="card" style="margin-bottom:16px"><h2>Rollback result</h2>${actionsTable(res.actions)}</div>`;
      toast("Rolled back", "ok");
      await refreshStatus();
      setTimeout(route, 1200);
    } catch (e) { toast(e.message, "err"); }
  }, { once: true });
  dlg.showModal();
  input.focus();
};

/* ------------------------------------------------------------------ settings extras */
function scheduleCard(st) {
  const clouds = state.status.default_providers;
  return `<section class="card" id="sec-schedule"><div class="card-head"><h2>Scheduled scans</h2>
      ${st.installed ? badge("Installed", "good") : badge("Not installed", "neutral")}</div>
    <p class="muted" style="margin-top:0">Runs a scan automatically with ${navigator.userAgent.includes("Windows") ? "Windows Task Scheduler" : "cron"},
      even when this dashboard is closed. History, drift detection and webhook alerts work as usual; results show here next time.</p>
    ${st.installed ? `<p class="small">${esc(st.detail)}</p>` : ""}
    <div class="toolbar">
      <label>Every <select id="sch-every">
        ${[[60, "hour"], [240, "4 hours"], [720, "12 hours"], [1440, "day"], [10080, "week"]].map(([v, l]) => `<option value="${v}" ${v === 1440 ? "selected" : ""}>${l}</option>`).join("")}
      </select></label>
      <span class="muted">clouds: ${esc(clouds.join(", ").toUpperCase())}</span>
      <label class="check"><input type="checkbox" id="sch-all"> all accounts</label>
      <button class="btn small primary" data-action="schedule-install">${st.installed ? "Update schedule" : "Install schedule"}</button>
      ${st.installed ? `<button class="btn small" data-action="schedule-remove">Remove</button>` : ""}
    </div></section>`;
}

function waiversCard(list) {
  return `<section class="card" id="sec-waivers"><div class="card-head"><h2>Accepted risks (waivers)</h2><span class="muted">${list.length} total</span></div>
    ${list.length ? `<div class="table-wrap"><table><thead><tr><th>Cloud</th><th>Resource</th><th>Check</th><th>Reason</th><th>Expires</th><th></th></tr></thead><tbody>
      ${list.map((w) => `<tr><td>${esc(w.provider.toUpperCase())}</td><td class="mono small">${esc(w.resource)}</td><td class="mono">${esc(w.check_id)}</td>
        <td>${esc(w.reason)}</td><td class="nowrap">${w.expired ? badge(`expired ${w.expires}`, "warn") : esc(w.expires)}</td>
        <td><button class="btn small" data-action="unwaive" data-id="${esc(w.id)}">Remove</button></td></tr>`).join("")}</tbody></table></div>`
      : `<p class="muted">None yet. Use "Accept risk" on a finding when something is intended, like a public website bucket.</p>`}</section>`;
}

actions["schedule-install"] = async (el) => {
  await withBusy(el, "Installing", async () => {
    try {
      const r = await api("/api/schedule", { method: "POST", body: { every: Number($("#sch-every").value),
        providers: state.status.default_providers, all_accounts: $("#sch-all").checked } });
      toast(r.message, "ok");
      renderSettings();
    } catch (e) { toast(e.message, "err"); }
  });
};
actions["schedule-remove"] = async (el) => {
  await withBusy(el, "Removing", async () => {
    try { toast((await api("/api/schedule", { method: "DELETE" })).message, "ok"); renderSettings(); } catch (e) { toast(e.message, "err"); }
  });
};
actions["migrate-secrets"] = async (el) => {
  await withBusy(el, "Moving", async () => {
    try {
      const r = await api("/api/settings/migrate-secrets", { method: "POST" });
      toast(r.moved.length ? `Moved to the OS keychain: ${r.moved.join(", ")}` : "Nothing to move", "ok");
      renderSettings();
    } catch (e) { toast(e.message, "err"); }
  });
};
actions["gcp-key"] = () => $("#gcp-key-file").click();

function bindGcpUpload() {
  const input = $("#gcp-key-file");
  if (!input) return;
  input.addEventListener("change", async () => {
    const file = input.files[0];
    if (!file) return;
    if (file.size > 32 * 1024) { toast("That file is too large to be a service-account key.", "err"); return; }
    try {
      const r = await api("/api/settings/gcp-key", { method: "POST", body: { content: await file.text() } });
      toast(`Key for ${r.client_email} saved (project ${r.project})`, "ok");
      await refreshStatus();
      await renderSettings();
      actions.test($("[data-action=test][data-cloud=gcp]"));
    } catch (e) { toast(e.message, "err"); }
    input.value = "";
  });
}

/* ------------------------------------------------------------------ first-run setup wizard */
const SETUP_STEPS = [["clouds", "Choose clouds"], ["signin", "Sign in"], ["options", "Options"], ["done", "Scan"]];

async function renderSetup(step) {
  const steps = `<ol class="steps">${SETUP_STEPS.map(([k, l], i) => `<li class="${k === step ? "on" : ""}"><span>${i + 1}</span>${esc(l)}</li>`).join("")}</ol>`;
  const head = `<div class="page-head"><div><h1>Set up CloudDetectX</h1>
      <div class="sub">A few steps to connect your clouds. Everything is stored locally; cloud credentials stay in each cloud's own store.</div></div>
      <div class="actions"><button class="btn" data-action="setup-skip">Skip setup</button></div></div>${steps}`;
  const data = await api("/api/settings");
  const section = (name) => data.sections.find((s) => s.name === name);
  const chosen = section("General").fields.find((f) => f.key === "CLOUDDETECTX_PROVIDERS").value.split(",").filter(Boolean);
  let body = "";
  if (step === "clouds") {
    body = `<div class="card"><h2>Which clouds do you use?</h2>
      <div class="toolbar" id="setup-clouds">${[["aws", "Amazon Web Services"], ["azure", "Microsoft Azure"], ["gcp", "Google Cloud"]].map(([k, l]) =>
        `<label class="check pick"><input type="checkbox" value="${k}" ${chosen.includes(k) ? "checked" : ""}> ${l}</label>`).join("")}</div>
      <button class="btn primary" data-action="setup-clouds">Next</button></div>`;
  } else if (step === "signin") {
    body = `<p class="secondary">Sign in to each cloud, then use <strong>Test connection</strong>. Scans are read-only.</p>
      <div class="stack">${chosen.map((p) => sectionHtml(section({ aws: "AWS", azure: "Azure", gcp: "GCP" }[p]))).join("")}</div>
      <div style="margin-top:16px"><a class="btn primary" href="#/setup/options">Next</a></div>`;
  } else if (step === "options") {
    body = `<div class="stack">${["Investigation", "Alerts"].map((n) => sectionHtml(section(n))).join("")}</div>
      <div style="margin-top:16px"><a class="btn" href="#/setup/signin">Back</a> <a class="btn primary" href="#/setup/done">Next</a></div>`;
  } else {
    body = `<div class="card empty"><h2>You're set</h2><p>Run the first scan now. It reads configuration only and changes nothing.</p>
      <button class="btn primary" data-action="setup-finish">Go to the dashboard and scan</button></div>`;
  }
  main.innerHTML = head + body;
  $$(".form-row").forEach(bindField);
  bindGcpUpload();
}

actions["setup-clouds"] = async (el) => {
  const picked = $$("#setup-clouds input:checked").map((i) => i.value);
  if (!picked.length) { toast("Choose at least one cloud", "err"); return; }
  await withBusy(el, "Saving", async () => {
    try {
      await api("/api/settings/CLOUDDETECTX_PROVIDERS", { method: "PUT", body: { value: picked.join(",") } });
      await refreshStatus();
      location.hash = "#/setup/signin";
    } catch (e) { toast(e.message, "err"); }
  });
};
actions["setup-skip"] = () => { store("clouddetectx.setup-skipped", "1"); location.hash = "#/dashboard"; };
actions["setup-finish"] = async () => {
  store("clouddetectx.setup-skipped", "1");
  await refreshStatus();
  state.cloud = state.status.default_providers[0] || "aws";
  location.hash = "#/dashboard";
  setTimeout(() => { const b = $("[data-action=scan]"); if (b) actions.scan(b); }, 300);
};
