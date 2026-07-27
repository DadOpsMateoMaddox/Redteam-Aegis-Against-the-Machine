// dashboard.js — Aegis red-team console frontend. No build step, no framework.

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

// ---------------------------------------------------------------- tabs ----
function showTab(name) {
  $$(".tab").forEach((el) => el.classList.toggle("hidden", el.id !== `tab-${name}`));
  $$(".topnav a").forEach((a) => a.classList.toggle("active", a.dataset.tab === name));
  if (name === "overview") loadOverview();
  if (name === "policy") loadPolicy();
  if (name === "findings") loadFindings();
  if (name === "runs") loadRuns();
}
$$(".topnav a").forEach((a) => a.addEventListener("click", () => showTab(a.dataset.tab)));

// --------------------------------------------------------------- clock ----
function tickClock() {
  $("#clock").textContent = new Date().toISOString().slice(11, 19) + " UTC";
}
setInterval(tickClock, 1000);
tickClock();

// ------------------------------------------------------------- helpers ----
function fmtTs(ts) {
  if (!ts) return "--";
  return new Date(ts * 1000).toLocaleString();
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// -------------------------------------------------------------- overview --
async function loadOverview() {
  const [ov, runsRes] = await Promise.all([
    fetch("/api/overview").then((r) => r.json()),
    fetch("/api/runs").then((r) => r.json()),
  ]);
  $("#kpi-runs").textContent = ov.run_count;
  $("#kpi-executed").textContent = ov.totals.executed;
  $("#kpi-blocked").textContent = ov.totals.blocked;
  $("#kpi-findings").textContent = ov.totals.findings;
  $("#kpi-proposed").textContent = ov.totals.proposed;

  if (!ov.latest_run_id) return;
  $("#latest-run-meta").textContent = `${ov.latest_run_id} · ${fmtTs(ov.latest_ts)}`;
  const latest = runsRes.find((r) => r.run_id === ov.latest_run_id);
  if (!latest) return;
  $("#latest-run-summary").innerHTML = `
    <div style="font-family: var(--mono); font-size: 12px; color: var(--text-dim);">
      <div><span style="color: var(--text-mute);">goal:</span> ${escapeHtml(latest.goal)}</div>
      <div><span style="color: var(--text-mute);">planner:</span> ${escapeHtml(latest.planner_label)}</div>
      <div><span style="color: var(--text-mute);">duration:</span> ${latest.duration_ms} ms</div>
      <div style="margin-top: 8px;">
        proposed ${latest.counts.proposed} · blocked ${latest.counts.blocked} ·
        executed ${latest.counts.executed} · allowed ${latest.counts.allowed} ·
        findings ${latest.counts.findings}
      </div>
    </div>`;
}

// --------------------------------------------------------------- policy ---
async function loadPolicy() {
  const p = await fetch("/api/policy").then((r) => r.json());
  $("#policy-risk-ceiling").textContent = `auto-approve ceiling: ${p.auto_approve_max_risk}`;

  $("#policy-actions").innerHTML = `
    <div class="policy-cell">
      <h4>allowed action types</h4>
      <div class="pill-row">${p.allowed_action_types.map((t) => `<span class="pill">${t}</span>`).join("")}</div>
    </div>
    <div class="policy-cell">
      <h4>risk levels</h4>
      <div class="pill-row">${p.risk_levels.map((r) => `<span class="pill ${r === "CRITICAL" || r === "HIGH" ? "crit" : ""}">${r}</span>`).join("")}</div>
    </div>
    <div class="policy-cell">
      <h4>repo scope</h4>
      <div class="pill-row"><span class="pill mono-cmd">${escapeHtml(p.repo_root)}</span></div>
    </div>`;

  const cmdRows = Object.entries(p.tool_broker.command_map)
    .map(([type, cmd]) => `
      <div class="policy-cell">
        <h4>${type}</h4>
        <div class="pill-row"><span class="pill mono-cmd">${cmd.join(" ")} &lt;target&gt;</span></div>
      </div>`).join("");
  $("#policy-tools").innerHTML = `
    <div class="policy-cell">
      <h4>allowed tools</h4>
      <div class="pill-row">${p.tool_broker.allowed_tools.map((t) => `<span class="pill">${t}</span>`).join("")}</div>
    </div>
    ${cmdRows}`;
}

// ------------------------------------------------------------- findings ---
function findingCard(f) {
  const sev = (f.severity || "info").toLowerCase();
  return `
    <div class="finding-card severity-${sev}">
      <div class="finding-title">
        <span>${escapeHtml(f.title)}</span>
        <span class="sev-tag">${sev}</span>
      </div>
      <div class="finding-desc">${escapeHtml(f.description)}</div>
      <ol class="finding-repro">${(f.reproduction || []).map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol>
      ${(f.evidence || []).map((e) => `
        <div class="finding-evidence">
          <code>${escapeHtml(e.kind)}</code> from <code>${escapeHtml(e.reference)}</code>
          — sha256 <code>${escapeHtml((e.sha256 || "").slice(0, 24))}...</code>
        </div>`).join("")}
      <div class="finding-meta">id ${escapeHtml(f.id)} · run ${escapeHtml(f.run_id || "")} · ${fmtTs(f.ts)}</div>
    </div>`;
}

async function loadFindings() {
  const findings = await fetch("/api/findings").then((r) => r.json());
  $("#findings-list").innerHTML = findings.length
    ? findings.map(findingCard).join("")
    : `<div class="empty-hint">No findings recorded yet.</div>`;
}

// ----------------------------------------------------------------- runs ---
function deltaCell(delta, key) {
  if (delta == null) return `<span class="delta flat">first run</span>`;
  const v = delta[key];
  if (v === 0) return `<span class="delta flat">0</span>`;
  const cls = v > 0 ? "up" : "down";
  return `<span class="delta ${cls}">${v > 0 ? "+" : ""}${v}</span>`;
}

async function loadRuns() {
  const runs = await fetch("/api/runs").then((r) => r.json());
  const tbody = $("#tbl-runs tbody");
  tbody.innerHTML = runs.map((r) => `
    <tr>
      <td>${escapeHtml(r.run_id)}</td>
      <td>${escapeHtml(r.planner_label)}</td>
      <td>${escapeHtml(r.goal)}</td>
      <td class="num">${r.counts.proposed}</td>
      <td class="num">${r.counts.blocked}</td>
      <td class="num">${r.counts.executed}</td>
      <td class="num">${r.counts.findings}</td>
      <td class="num">${deltaCell(r.delta, "blocked")}</td>
      <td class="num">${r.duration_ms} ms</td>
    </tr>`).join("") || `<tr><td colspan="9"><div class="empty-hint">No runs yet.</div></td></tr>`;
}

// -------------------------------------------------------------- pipeline --
function stepCard(step) {
  const a = step.action;
  const reason = step.reason ? `<div class="step-reason">${escapeHtml(step.reason)}</div>` : "";
  const out = step.output
    ? `<div class="step-reason">exit ${step.output.returncode} — ${escapeHtml((step.output.cmd || []).join(" "))}</div>`
    : "";
  return `
    <div class="step-card ${step.status}">
      <span class="marker"></span>
      <span class="status-tag">${step.status}</span>
      <span class="action-type">${escapeHtml(a.type)}</span>
      <span class="target">${escapeHtml(a.target)} — ${escapeHtml(a.rationale)}</span>
      <span class="risk risk-${a.risk.toLowerCase()}">${a.risk}</span>
    </div>
    ${reason}${out}`;
}

let feedBuffer = [];
function renderFeed() {
  $("#step-feed").innerHTML = feedBuffer.length
    ? feedBuffer.map(stepCard).join("")
    : `<div class="empty-hint">No steps yet. Trigger a run above.</div>`;
}

async function triggerRun() {
  const goal = $("#goal-input").value.trim();
  if (!goal) return;
  const btn = $("#run-btn");
  btn.disabled = true;
  $("#run-status").textContent = "running...";
  feedBuffer = [];
  renderFeed();
  try {
    const resp = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ goal }),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }));
      $("#run-status").textContent = `error: ${err.detail}`;
      return;
    }
    // step cards stream in over the websocket; this just confirms completion
    $("#run-status").textContent = "done";
  } catch (e) {
    $("#run-status").textContent = `error: ${e}`;
  } finally {
    btn.disabled = false;
  }
}
$("#run-btn").addEventListener("click", triggerRun);
$("#goal-input").addEventListener("keydown", (e) => { if (e.key === "Enter") triggerRun(); });

// ------------------------------------------------------------- websocket --
function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);

  ws.onopen = () => {
    $("#ws-pill").className = "status-pill ok";
    $("#ws-pill").innerHTML = '<span class="dot"></span> WS LIVE';
  };
  ws.onclose = () => {
    $("#ws-pill").className = "status-pill crit";
    $("#ws-pill").innerHTML = '<span class="dot"></span> WS DISCONNECTED';
    setTimeout(connectWs, 2000);
  };
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.kind === "run_start") {
      feedBuffer = [];
      renderFeed();
      $("#pipeline-run-id").textContent = `${msg.run_id} — ${msg.goal}`;
    } else if (msg.kind === "step") {
      feedBuffer.push(msg.step);
      renderFeed();
    } else if (msg.kind === "run_done") {
      $("#pipeline-run-id").textContent = `${msg.run_id} — complete`;
      $("#run-status").textContent = "done";
    } else if (msg.kind === "run_error") {
      $("#run-status").textContent = `error: ${msg.error}`;
    }
  };
}
connectWs();

// ------------------------------------------------------------------ init --
loadOverview();
