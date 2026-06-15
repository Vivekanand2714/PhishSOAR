/* ============================================================
   PhishSOAR Dashboard — Frontend JavaScript
   Polls /api/status every second and updates UI in real-time
   ============================================================ */

const API = "http://localhost:5000";
let pollInterval   = null;
let currentView    = "dashboard";
let lastResult     = null;
let particleCanvas, particleCtx, particles = [];

// ─────────────────────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  initClock();
  initParticles();
  loadReports();
  // Start polling immediately to catch any running playbook
  startPolling();
});

// ─────────────────────────────────────────────────────────────
// CLOCK
// ─────────────────────────────────────────────────────────────
function initClock() {
  function tick() {
    const now = new Date();
    document.getElementById("clock").textContent =
      now.toUTCString().slice(17, 25) + " UTC";
  }
  tick();
  setInterval(tick, 1000);
}

// ─────────────────────────────────────────────────────────────
// BACKGROUND PARTICLES
// ─────────────────────────────────────────────────────────────
function initParticles() {
  particleCanvas = document.getElementById("bg-canvas");
  particleCtx    = particleCanvas.getContext("2d");
  resizeCanvas();
  window.addEventListener("resize", resizeCanvas);
  createParticles();
  animateParticles();
}

function resizeCanvas() {
  particleCanvas.width  = window.innerWidth;
  particleCanvas.height = window.innerHeight;
}

function createParticles() {
  particles = [];
  const count = Math.floor((window.innerWidth * window.innerHeight) / 15000);
  for (let i = 0; i < count; i++) {
    particles.push({
      x:  Math.random() * window.innerWidth,
      y:  Math.random() * window.innerHeight,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r:  Math.random() * 1.5 + 0.5,
      alpha: Math.random() * 0.5 + 0.1,
    });
  }
}

function animateParticles() {
  particleCtx.clearRect(0, 0, particleCanvas.width, particleCanvas.height);
  const color = "99, 102, 241"; // accent

  particles.forEach(p => {
    p.x += p.vx; p.y += p.vy;
    if (p.x < 0) p.x = particleCanvas.width;
    if (p.x > particleCanvas.width)  p.x = 0;
    if (p.y < 0) p.y = particleCanvas.height;
    if (p.y > particleCanvas.height) p.y = 0;

    particleCtx.beginPath();
    particleCtx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
    particleCtx.fillStyle = `rgba(${color}, ${p.alpha})`;
    particleCtx.fill();
  });

  // Draw connections
  for (let i = 0; i < particles.length; i++) {
    for (let j = i + 1; j < particles.length; j++) {
      const dx = particles[i].x - particles[j].x;
      const dy = particles[i].y - particles[j].y;
      const dist = Math.sqrt(dx*dx + dy*dy);
      if (dist < 120) {
        particleCtx.beginPath();
        particleCtx.moveTo(particles[i].x, particles[i].y);
        particleCtx.lineTo(particles[j].x, particles[j].y);
        particleCtx.strokeStyle = `rgba(${color}, ${0.15 * (1 - dist/120)})`;
        particleCtx.lineWidth = 0.5;
        particleCtx.stroke();
      }
    }
  }
  requestAnimationFrame(animateParticles);
}

// ─────────────────────────────────────────────────────────────
// VIEW SWITCHING
// ─────────────────────────────────────────────────────────────
function switchView(view) {
  currentView = view;
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));

  document.getElementById(`view-${view}`)?.classList.add("active");
  document.querySelector(`.nav-item[data-view="${view}"]`)?.classList.add("active");

  const titles = {
    dashboard:  ["PhishSOAR Dashboard",    "MITRE ATT&CK T1566 • T1598"],
    iocs:       ["IoC Explorer",          "Extracted Indicators of Compromise"],
    reports:    ["Incident Reports",      "Generated tickets and HTML reports"],
    mitre:      ["MITRE ATT&CK Coverage", "Technique mapping for phishing response"],
    mailclient: ["Mailing Client Mode",   "Multi-account email triage and inspection"],
  };
  document.getElementById("page-title").textContent    = titles[view]?.[0] || view;
  document.getElementById("page-subtitle").textContent = titles[view]?.[1] || "";

  if (view === "reports") loadReports();
  if (view === "iocs" && lastResult) renderIocTable(lastResult);
  if (view === "mailclient") loadAccounts();
}

// ─────────────────────────────────────────────────────────────
// RUN PLAYBOOK
// ─────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────
// TRIGGER PLAYBOOK / RUN MONITORING
// ─────────────────────────────────────────────────────────────
async function triggerPlaybook(source = "demo") {
  const isDemo = source === "demo";

  document.getElementById("btn-demo").disabled = true;
  document.getElementById("btn-gmail").disabled = true;
  document.getElementById("btn-outlook").disabled = true;
  document.getElementById("btn-joint").disabled = true;

  resetPipeline();

  if (!isDemo) {
    document.getElementById("loading-overlay").classList.remove("hidden");
  }

  try {
    const resp = await fetch(`${API}/api/run`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ demo: isDemo, source })
    });
    const data = await resp.json();

    if (data.error) {
      alert("Error: " + data.error);
      enableAllButtons();
      return;
    }

    document.getElementById("loading-overlay").classList.add("hidden");
    startPolling();
  } catch (e) {
    document.getElementById("loading-overlay").classList.add("hidden");
    alert("Cannot connect to PhishSOAR server. Make sure server.py is running.");
    enableAllButtons();
  }
}

function enableAllButtons() {
  document.getElementById("btn-demo").disabled = false;
  document.getElementById("btn-gmail").disabled = false;
  document.getElementById("btn-outlook").disabled = false;
  document.getElementById("btn-joint").disabled = false;
}

// ─────────────────────────────────────────────────────────────
// POLLING
// ─────────────────────────────────────────────────────────────
function startPolling() {
  if (pollInterval) return;
  pollInterval = setInterval(pollStatus, 1200);
  pollStatus(); // immediate first call
}

function stopPolling() {
  if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
  enableAllButtons();
}

async function pollStatus() {
  try {
    const resp = await fetch(`${API}/api/status`);
    const state = await resp.json();
    updateDashboard(state);

    if (!state.running && state.stage !== "idle") {
      stopPolling();
      if (state.result) lastResult = state.result;
    }
  } catch (e) {
    // Server not running — show hint
    console.warn("PhishSOAR server not reachable:", e);
  }
}

// ─────────────────────────────────────────────────────────────
// UPDATE DASHBOARD FROM STATE
// ─────────────────────────────────────────────────────────────
function updateDashboard(state) {
  const { running, stage, stages = [], result, elapsed, mode, queue_size, queue_index, source } = state;

  // Update Queue / Polling Status Badge
  const queueBadge = document.getElementById("queue-status-badge");
  const queueText = document.getElementById("queue-status-text");
  
  if (queueBadge && queueText) {
    if (mode === "backfill") {
      queueBadge.classList.remove("hidden");
      queueText.textContent = `Queue Ingestion: ${queue_index}/${queue_size}`;
    } else if (mode === "monitoring") {
      queueBadge.classList.remove("hidden");
      queueText.textContent = `Live Monitoring (${source.toUpperCase()})`;
    } else {
      queueBadge.classList.add("hidden");
    }
  }

  // Sidebar status
  const dot  = document.querySelector(".status-dot");
  const text = document.querySelector(".status-text");
  if (running) {
    dot.className  = "status-dot running";
    text.textContent = `Running: ${stage}`;
  } else if (stage === "complete") {
    dot.className  = "status-dot complete";
    text.textContent = "Playbook Complete";
  } else if (stage === "error") {
    dot.className  = "status-dot error";
    text.textContent = "Error occurred";
  } else {
    dot.className  = "status-dot idle";
    text.textContent = "System Idle";
  }

  // Update pipeline stages
  stages.forEach(s => updateStage(s));

  // Elapsed time
  if (elapsed) {
    document.getElementById("stat-elapsed").textContent = `${elapsed}s`;
  }

  // Render result if complete
  if (result && result.success) {
    if (!lastResult || lastResult.ticket_id !== result.ticket_id) {
      if (currentView === "mailclient") {
        loadMails();
      }
    }
    renderResult(result);
  } else if (result && !result.success) {
    showError(result.error);
  }
}

// ─────────────────────────────────────────────────────────────
// PIPELINE STAGE UPDATE
// ─────────────────────────────────────────────────────────────
function updateStage(stage) {
  const el = document.getElementById(`stage-${stage.name}`);
  if (!el) return;

  el.className = `pipeline-stage ${stage.status}`;
  const badge = el.querySelector(".stage-status-badge");

  const labels = {
    waiting:  "WAITING",
    running:  "RUNNING...",
    complete: "✓ DONE",
    error:    "✗ ERROR",
  };
  if (badge) badge.textContent = labels[stage.status] || stage.status.toUpperCase();

  // Show stage data
  const data = stage.data || {};
  if (stage.status === "complete" && Object.keys(data).length > 0) {
    let info = "";
    if (data.subject) info = data.subject.substring(0,30) + "…";
    else if (data.urls !== undefined) info = `${data.urls} URLs · ${data.keywords} kw`;
    else if (data.malicious !== undefined) info = `${data.malicious} mal · ${data.suspicious} sus`;
    else if (data.verdict) info = `${data.verdict} (${data.score}/100)`;
    else if (data.actions_taken) info = data.actions_taken.join(", ");
    else if (data.ticket_id) info = data.ticket_id;

    if (info) {
      let desc = el.querySelector(".stage-desc");
      if (desc) desc.textContent = info;
    }
  }
}

// ─────────────────────────────────────────────────────────────
// RENDER FINAL RESULT
// ─────────────────────────────────────────────────────────────
function renderResult(result) {
  const verdict     = result.verdict || "CLEAN";
  const score       = result.score || 0;
  const triage      = result.triage || {};
  const iocs        = result.iocs || {};
  const enrichment  = result.enrichment || {};
  const response    = result.response || {};
  const ticket      = result.ticket || {};
  const emailInfo   = ticket.email || {};

  // Stats
  const urlCount = (iocs.urls||[]).length + (iocs.domains||[]).length;
  document.getElementById("stat-score").textContent   = `${score}/100`;
  document.getElementById("stat-urls").textContent    = urlCount;
  document.getElementById("stat-verdict").textContent = verdict;
  document.getElementById("stat-elapsed").textContent = `${result.elapsed_sec}s`;

  // Verdict card
  const verdictSection = document.getElementById("verdict-section");
  verdictSection.classList.remove("hidden");

  const verdictCard = document.getElementById("verdict-card");
  verdictCard.className = `verdict-card ${verdict.toLowerCase()}`;

  const emojiMap = { MALICIOUS: "🔴", SUSPICIOUS: "🟡", CLEAN: "🟢" };
  document.getElementById("verdict-emoji").textContent = emojiMap[verdict] || "⚪";
  document.getElementById("verdict-text").textContent  = verdict;
  document.getElementById("verdict-score").textContent = `Score: ${score}/100 • ${triage.action || ""}`;

  // Verdict action badges
  const actionsEl = document.getElementById("verdict-actions");
  actionsEl.innerHTML = "";
  const actions = response.actions_taken || [];
  if (actions.includes("email_quarantined")) {
    actionsEl.innerHTML += `<div class="action-badge action-quarantine">✅ Email Quarantined</div>`;
  }
  if (actions.includes("iocs_blocked")) {
    actionsEl.innerHTML += `<div class="action-badge action-block">🚫 IoCs Blocked</div>`;
  }
  actionsEl.innerHTML += `<div class="action-badge action-notify">📢 Alert Sent</div>`;

  // SLA badge
  const slaBadge = document.getElementById("sla-badge");
  if (result.within_sla) {
    slaBadge.className = "sla-badge sla-ok";
    slaBadge.textContent = `✅ SLA Met (${result.elapsed_sec}s / 60s)`;
  } else {
    slaBadge.className = "sla-badge sla-fail";
    slaBadge.textContent = `❌ SLA Breached (${result.elapsed_sec}s / 60s)`;
  }

  // Email info card
  document.getElementById("email-info").innerHTML = `
    <div class="info-field"><div class="info-label">Subject</div><div class="info-value">${emailInfo.subject || "N/A"}</div></div>
    <div class="info-field"><div class="info-label">From</div><div class="info-value">${emailInfo.sender || "N/A"}</div></div>
    <div class="info-field"><div class="info-label">To</div><div class="info-value">${emailInfo.to || "N/A"}</div></div>
    <div class="info-field"><div class="info-label">Date</div><div class="info-value">${emailInfo.date || "N/A"}</div></div>
  `;

  // Sender Trust Card rendering
  const senderTrust = enrichment.sender_trust || result.sender_trust || (result.ticket ? result.ticket.sender_trust : null);
  if (senderTrust) {
    const trustScore = senderTrust.trust_score !== undefined ? senderTrust.trust_score : 100;
    const trustLevel = senderTrust.trust_level || "TRUSTED";
    const checks = senderTrust.checks || {};
    
    const tls = checks.tls || {};
    const spf = checks.spf || {};
    const dkim = checks.dkim || {};
    const dmarc = checks.dmarc || {};
    const mx = checks.mx || {};

    const trustColors = {
      TRUSTED: "var(--success)",
      SUSPICIOUS: "var(--warning)",
      UNTRUSTED: "var(--danger)",
      SPOOFED: "var(--danger)",
      ERROR: "var(--text-muted)"
    };
    const tcolor = trustColors[trustLevel] || "var(--text-muted)";

    const getStatusText = (passed, label) => {
      return passed 
        ? `<span class="trust-badge-pass">✓ ${label}</span>`
        : `<span class="trust-badge-fail">✗ ${label}</span>`;
    };

    document.getElementById("sender-trust-info").innerHTML = `
      <div class="sender-trust-score-container">
        <div class="sender-trust-score" style="color: ${tcolor}">${trustScore}</div>
        <div>
          <div class="sender-trust-level" style="color: ${tcolor}">${trustLevel}</div>
          <div class="info-label" style="margin-top: 2px;">AUTHENTICITY SCORE</div>
        </div>
      </div>
      <table class="sender-trust-table">
        <tbody>
          <tr>
            <td>SSL/TLS Cert</td>
            <td>${getStatusText(tls.cert_valid, tls.cert_valid ? "Valid" : (tls.error ? tls.error.substring(0, 18) + '...' : "Invalid"))}</td>
          </tr>
          <tr>
            <td>SPF Record</td>
            <td>${getStatusText(spf.has_spf, spf.has_spf ? "Pass" : "Fail/None")}</td>
          </tr>
          <tr>
            <td>DKIM Key</td>
            <td>${getStatusText(dkim.has_dkim, dkim.has_dkim ? "Pass" : "Fail/None")}</td>
          </tr>
          <tr>
            <td>DMARC Policy</td>
            <td>${getStatusText(dmarc.has_dmarc, dmarc.has_dmarc ? (dmarc.policy || "Pass") : "Fail/None")}</td>
          </tr>
          <tr>
            <td>MX Records</td>
            <td>${getStatusText(mx.has_mx, mx.has_mx ? "Pass" : "Fail/None")}</td>
          </tr>
        </tbody>
      </table>
    `;
  } else {
    document.getElementById("sender-trust-info").innerHTML = `
      <div class="empty-state">No sender trust data available</div>
    `;
  }

  // Enrichment card
  const enSummary = enrichment.summary || {};
  document.getElementById("enrichment-info").innerHTML = `
    <div class="intel-grid">
      <div class="intel-item mal"><div class="intel-count">${enSummary.malicious||0}</div><div class="intel-label">Malicious</div></div>
      <div class="intel-item sus"><div class="intel-count">${enSummary.suspicious||0}</div><div class="intel-label">Suspicious</div></div>
      <div class="intel-item cln"><div class="intel-count">${enSummary.clean||0}</div><div class="intel-label">Clean</div></div>
      <div class="intel-item tot"><div class="intel-count">${enSummary.total_checked||0}</div><div class="intel-label">Total Checked</div></div>
    </div>
  `;

  // Risk indicators
  const risks = [...(iocs.risk_indicators||[]), ...(iocs.header_anomalies||[])];
  if (risks.length > 0) {
    document.getElementById("risks-info").innerHTML =
      risks.map(r => `<div class="risk-item">${r}</div>`).join("");
  } else {
    document.getElementById("risks-info").innerHTML =
      `<div class="empty-state">No risk indicators detected</div>`;
  }

  // IoC table (for IoC view)
  renderIocTable(result);

  // Gemma Advisor card
  const gemmaAdvisory = result.gemma_advisory || result.ticket?.gemma_advisory;
  const gemmaInfoEl = document.getElementById("gemma-advisor-info");
  if (gemmaInfoEl) {
    if (gemmaAdvisory) {
      let formatted = escHtml(gemmaAdvisory);
      // Clean up markdown / format slightly for a premium feel
      formatted = formatted.replace(/###\s*(.*?)(?:\r?\n|$)/g, '<h4 style="color: #a5b4fc; margin-top: 14px; margin-bottom: 8px; font-weight: 700; font-size: 0.95rem; display: flex; align-items: center; gap: 6px;">$1</h4>');
      formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong style="color: var(--text); font-weight: 600;">$1</strong>');
      formatted = formatted.replace(/(?:^|\n)[-*]\s+(.*?)(?:\r?\n|$)/g, '\n<div style="margin-left: 16px; margin-bottom: 6px; display: flex; align-items: flex-start; gap: 8px;"><span>•</span> <span>$1</span></div>');
      formatted = formatted.replace(/\r?\n\r?\n/g, '<div style="margin-bottom: 12px;"></div>');
      formatted = formatted.replace(/\r?\n/g, '<br>');

      gemmaInfoEl.innerHTML = `<div style="font-family: inherit; font-size: 0.88rem; line-height: 1.6; color: var(--text);">${formatted}</div>`;
    } else {
      gemmaInfoEl.innerHTML = `<div class="empty-state">No AI advisory recommendations generated (clean or unanalyzed email)</div>`;
    }
  }

  // Report links
  if (result.ticket_id) {
    const reportSection = document.getElementById("report-link-section");
    reportSection.classList.remove("hidden");
    document.getElementById("report-link").href  = `${API}/api/report/${result.ticket_id}`;
    document.getElementById("ticket-link").href  = `${API}/api/ticket/${result.ticket_id}`;
  }
}

// ─────────────────────────────────────────────────────────────
// IoC TABLE
// ─────────────────────────────────────────────────────────────
function renderIocTable(result) {
  const iocs = result.iocs || result.ticket?.iocs || {};
  const container = document.getElementById("ioc-table-container");
  if (!container) return;

  const rows = [];

  (iocs.urls || []).forEach(url => {
    rows.push(`<tr>
      <td><span class="ioc-badge ioc-url">URL</span></td>
      <td class="ioc-value-cell">${escHtml(url.substring(0,100))}</td>
      <td><span class="risk-badge risk-high">CHECK</span></td>
    </tr>`);
  });

  (iocs.domains || []).forEach(d => {
    rows.push(`<tr>
      <td><span class="ioc-badge ioc-domain">DOMAIN</span></td>
      <td class="ioc-value-cell">${escHtml(d)}</td>
      <td><span class="risk-badge risk-med">CHECK</span></td>
    </tr>`);
  });

  (iocs.attachments || []).forEach(a => {
    const riskClass = a.suspicious ? "risk-high" : "risk-low";
    const riskText  = a.suspicious ? "SUSPICIOUS" : "CLEAN";
    rows.push(`<tr>
      <td><span class="ioc-badge ioc-att">ATTACHMENT</span></td>
      <td class="ioc-value-cell">${escHtml(a.filename)} (${a.mimeType})</td>
      <td><span class="risk-badge ${riskClass}">${riskText}</span></td>
    </tr>`);
  });

  (iocs.keywords_found || []).forEach(kw => {
    rows.push(`<tr>
      <td><span class="ioc-badge ioc-kw">KEYWORD</span></td>
      <td class="ioc-value-cell">${escHtml(kw)}</td>
      <td><span class="risk-badge risk-med">PHISHING</span></td>
    </tr>`);
  });

  if (rows.length === 0) {
    container.innerHTML = `<div class="empty-state">No IoCs found</div>`;
    return;
  }

  container.innerHTML = `
    <table class="ioc-table">
      <thead><tr><th>Type</th><th>Indicator</th><th>Risk</th></tr></thead>
      <tbody>${rows.join("")}</tbody>
    </table>
  `;
}

// ─────────────────────────────────────────────────────────────
// LOAD REPORTS LIST
// ─────────────────────────────────────────────────────────────
async function loadReports() {
  try {
    const resp = await fetch(`${API}/api/reports`);
    const reports = await resp.json();
    const el = document.getElementById("reports-list");

    if (!reports || reports.length === 0) {
      el.innerHTML = `<div class="empty-state">No reports generated yet. Run the playbook first.</div>`;
      return;
    }

    el.innerHTML = reports.map(r => `
      <div class="report-row">
        <div class="report-id">${r.ticket_id}</div>
        <div class="report-links">
          <a href="${API}${r.html_url}" target="_blank" class="btn btn-primary btn-sm">HTML Report</a>
          <a href="${API}${r.json_url}" target="_blank" class="btn btn-demo btn-sm">JSON Ticket</a>
        </div>
      </div>
    `).join("");
  } catch (e) {
    document.getElementById("reports-list").innerHTML =
      `<div class="empty-state">Cannot load reports (server offline)</div>`;
  }
}

// ─────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────
function resetPipeline() {
  document.querySelectorAll(".pipeline-stage").forEach(el => {
    el.className = "pipeline-stage";
    const badge = el.querySelector(".stage-status-badge");
    if (badge) badge.textContent = "WAITING";
    const desc = el.querySelector(".stage-desc");
    // restore original descriptions
    const descs = {
      ingestion:  "Gmail OAuth → Fetch email",
      extraction: "URLs · Domains · Attachments",
      enrichment: "VirusTotal · URLScan.io",
      triage:     "Score · Verdict · Action",
      response:   "Quarantine · Block · Notify",
      reporting:  "Ticket · HTML Report",
    };
    const stageName = el.dataset.stage;
    if (desc && descs[stageName]) desc.textContent = descs[stageName];
  });

  document.getElementById("verdict-section").classList.add("hidden");
  document.getElementById("report-link-section").classList.add("hidden");
  document.getElementById("stat-score").textContent   = "—";
  document.getElementById("stat-urls").textContent    = "—";
  document.getElementById("stat-verdict").textContent = "RUNNING";
  document.getElementById("email-info").innerHTML      = `<div class="empty-state">Fetching email...</div>`;
  document.getElementById("sender-trust-info").innerHTML = `<div class="empty-state">Awaiting authenticity check...</div>`;
  document.getElementById("enrichment-info").innerHTML = `<div class="empty-state">Awaiting enrichment...</div>`;
  document.getElementById("risks-info").innerHTML      = `<div class="empty-state">Running analysis...</div>`;
  const gemmaInfoEl = document.getElementById("gemma-advisor-info");
  if (gemmaInfoEl) {
    gemmaInfoEl.innerHTML = `<div class="empty-state">Awaiting analysis for AI security recommendations...</div>`;
  }
}

function showError(msg) {
  document.getElementById("stat-verdict").textContent = "ERROR";
  document.getElementById("email-info").innerHTML =
    `<div class="empty-state" style="color:#f87171">Error: ${escHtml(msg)}</div>`;
}

function escHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─────────────────────────────────────────────────────────────
// MAILING CLIENT STATE AND LOGIC
// ─────────────────────────────────────────────────────────────
let currentAccount = null;
let currentFolder = "inbox";
let allMails = [];
let activeMailId = null;

async function loadAccounts() {
  try {
    const resp = await fetch(`${API}/api/accounts`);
    const accounts = await resp.json();
    const listEl = document.getElementById("mail-accounts-list");
    if (!listEl) return;
    
    if (accounts.length === 0) {
      listEl.innerHTML = `<div class="empty-state" style="padding:10px; font-size:0.75rem;">No accounts linked</div>`;
      currentAccount = null;
      document.getElementById("mail-list").innerHTML = `<div class="empty-state">Link an account to get started</div>`;
      document.getElementById("mail-read-pane").innerHTML = `<div class="empty-state">No email selected</div>`;
      return;
    }
    
    listEl.innerHTML = accounts.map(acc => {
      const activeClass = currentAccount === acc.id || (!currentAccount && accounts[0].id === acc.id) ? "active" : "";
      if (!currentAccount && activeClass === "active") {
        currentAccount = acc.id;
      }
      return `
        <div class="account-item ${activeClass}" onclick="selectAccount('${acc.id}')">
          <div class="account-email" title="${acc.email}">${acc.email}</div>
          <div style="display:flex; align-items:center; gap:6px;">
            <span class="account-provider">${acc.provider}</span>
            <span style="color:var(--danger); cursor:pointer; font-weight:bold; font-size:0.9rem;" onclick="deleteAccount('${acc.id}', event)">&times;</span>
          </div>
        </div>
      `;
    }).join("");
    
    loadMails();
  } catch (e) {
    console.error("Error loading accounts:", e);
  }
}

function selectAccount(accountId) {
  currentAccount = accountId;
  document.querySelectorAll(".account-item").forEach(item => {
    item.classList.remove("active");
  });
  loadAccounts();
}

function selectFolder(folder) {
  currentFolder = folder;
  document.querySelectorAll(".folder-item").forEach(item => {
    if (item.dataset.folder === folder) {
      item.classList.add("active");
    } else {
      item.classList.remove("active");
    }
  });
  loadMails();
}

async function loadMails() {
  if (!currentAccount) return;
  try {
    const resp = await fetch(`${API}/api/mails?account_id=${currentAccount}&folder=${currentFolder}`);
    allMails = await resp.json();
    renderMailsList(allMails);
  } catch (e) {
    console.error("Error loading mails:", e);
  }
}

function renderMailsList(mails) {
  const listEl = document.getElementById("mail-list");
  if (!listEl) return;
  
  if (mails.length === 0) {
    listEl.innerHTML = `<div class="empty-state">No emails in this folder</div>`;
    return;
  }
  
  listEl.innerHTML = mails.map(m => {
    const unreadClass = m.is_read ? "" : "unread";
    const activeClass = activeMailId === m.id ? "active" : "";
    const dateFormatted = m.date ? m.date.substring(0, 16) : "";
    
    let tagClass = "clean";
    if (m.verdict === "MALICIOUS") tagClass = "malicious";
    else if (m.verdict === "SUSPICIOUS") tagClass = "suspicious";
    
    return `
      <div class="mail-list-item ${unreadClass} ${activeClass}" onclick="selectMail('${m.id}')">
        <div class="mail-item-header">
          <span class="mail-item-sender">${escHtml(m.sender)}</span>
          <span class="mail-item-date">${escHtml(dateFormatted)}</span>
        </div>
        <div class="mail-item-subject">${escHtml(m.subject || "(No Subject)")}</div>
        <div class="mail-item-snippet">${escHtml(m.snippet || "")}</div>
        <div class="mail-item-meta">
          <span class="verdict-tag ${tagClass}">${m.verdict}</span>
          <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:var(--text-muted);">${m.score}/100</span>
        </div>
      </div>
    `;
  }).join("");
}

async function selectMail(emailId) {
  activeMailId = emailId;
  document.querySelectorAll(".mail-list-item").forEach(item => {
    item.classList.remove("active");
  });
  loadMails();
  
  const readPane = document.getElementById("mail-read-pane");
  if (!readPane) return;
  
  readPane.innerHTML = `<div class="empty-state"><div class="loading-spinner" style="width:24px; height:24px; border-width:2px; margin-bottom:8px;"></div>Loading details...</div>`;
  
  try {
    await fetch(`${API}/api/mails/${emailId}/read`, { method: "POST" });
    
    const resp = await fetch(`${API}/api/mails/${emailId}`);
    const mail = await resp.json();
    
    const ticket = mail.ticket || {};
    const senderTrust = ticket.sender_trust || {};
    const trustScore = senderTrust.trust_score !== undefined ? senderTrust.trust_score : "N/A";
    const trustLevel = senderTrust.trust_level || "UNKNOWN";
    
    let tagClass = "clean";
    if (mail.verdict === "MALICIOUS") tagClass = "malicious";
    else if (mail.verdict === "SUSPICIOUS") tagClass = "suspicious";
    
    let advisoryHtml = "";
    if (mail.gemma_advisory) {
      let formatted = escHtml(mail.gemma_advisory);
      formatted = formatted.replace(/###\s*(.*?)(?:\r?\n|$)/g, '<h4 style="color: #a5b4fc; margin-top: 10px; margin-bottom: 6px; font-weight: 700; font-size: 0.88rem;">$1</h4>');
      formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong style="color: var(--text); font-weight: 600;">$1</strong>');
      formatted = formatted.replace(/(?:^|\n)[-*]\s+(.*?)(?:\r?\n|$)/g, '\n<div style="margin-left: 12px; margin-bottom: 4px; display: flex; align-items: flex-start; gap: 6px;"><span>•</span> <span>$1</span></div>');
      formatted = formatted.replace(/\r?\n\r?\n/g, '<div style="margin-bottom: 8px;"></div>');
      formatted = formatted.replace(/\r?\n/g, '<br>');
      
      advisoryHtml = `
        <div class="card" style="border-left: 3px solid var(--accent); background:rgba(99, 102, 241, 0.04); margin-bottom: 16px; padding: 14px 18px;">
          <div style="display:flex; align-items:center; gap:8px; font-weight:700; font-size:0.8rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--accent); margin-bottom:8px;">
            🤖 Gemma AI Security Advisor
          </div>
          <div style="font-size: 0.8rem; line-height: 1.5; color: var(--text);">${formatted}</div>
        </div>
      `;
    }
    
    const triageHtml = `
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 16px;">
        <div class="intel-item ${tagClass}" style="padding:8px 12px; text-align:center;">
          <div class="intel-count" style="font-size:1.1rem; text-transform: uppercase;">${mail.verdict}</div>
          <div class="intel-label" style="font-size:0.6rem;">PhishSOAR Verdict</div>
        </div>
        <div class="intel-item" style="padding:8px 12px; text-align:center; background:var(--surface3); border-color:var(--border);">
          <div class="intel-count" style="font-size:1.1rem; color:var(--text);">${mail.score}/100</div>
          <div class="intel-label" style="font-size:0.6rem;">Threat Score</div>
        </div>
        <div class="intel-item" style="padding:8px 12px; text-align:center; background:var(--surface3); border-color:var(--border);">
          <div class="intel-count" style="font-size:1.1rem; color:${trustLevel === 'SPOOFED' || trustLevel === 'UNTRUSTED' ? 'var(--danger)' : 'var(--success)'};">${trustScore}/100</div>
          <div class="intel-label" style="font-size:0.6rem;">Sender Authenticity (${trustLevel})</div>
        </div>
      </div>
    `;
    
    readPane.innerHTML = `
      <div class="mail-header-details">
        <div class="mail-subject-large">${escHtml(mail.subject || "(No Subject)")}</div>
        <div class="mail-meta-row">
          <div>From: <strong>${escHtml(mail.sender)}</strong></div>
          <div>Date: <strong>${escHtml(mail.date)}</strong></div>
        </div>
      </div>
      
      ${advisoryHtml}
      ${triageHtml}
      
      <div class="mail-section-title">Email Content</div>
      <div class="mail-body-content">${escHtml(mail.body_plain || "(Empty Body)")}</div>
    `;
    
  } catch (e) {
    console.error("Error fetching mail details:", e);
    readPane.innerHTML = `<div class="empty-state" style="color:var(--danger)">Error loading email details</div>`;
  }
}

function filterMails() {
  const query = document.getElementById("mail-search-input").value.toLowerCase();
  const filtered = allMails.filter(m => 
    (m.subject || "").toLowerCase().includes(query) ||
    (m.sender || "").toLowerCase().includes(query) ||
    (m.snippet || "").toLowerCase().includes(query)
  );
  renderMailsList(filtered);
}

function showAddAccountModal() {
  const modal = document.getElementById("add-account-modal");
  if (modal) modal.classList.remove("hidden");
}

function hideAddAccountModal() {
  const modal = document.getElementById("add-account-modal");
  if (modal) modal.classList.add("hidden");
  document.getElementById("acc-email").value = "";
  document.getElementById("acc-provider").value = "mock";
  document.getElementById("real-provider-hint").classList.add("hidden");
}

function toggleProviderFields() {
  const provider = document.getElementById("acc-provider").value;
  const hint = document.getElementById("real-provider-hint");
  if (provider === "mock") {
    hint.classList.add("hidden");
  } else {
    hint.classList.remove("hidden");
  }
}

async function submitAddAccount() {
  const email = document.getElementById("acc-email").value.trim();
  const provider = document.getElementById("acc-provider").value;
  
  if (!email || !email.includes("@")) {
    alert("Please enter a valid email address.");
    return;
  }
  
  try {
    const resp = await fetch(`${API}/api/accounts/add`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, provider })
    });
    const result = await resp.json();
    if (result.error) {
      alert("Error: " + result.error);
    } else {
      currentAccount = result.id;
      hideAddAccountModal();
      loadAccounts();
    }
  } catch (e) {
    alert("Failed to connect to server.");
  }
}

async function deleteAccount(accountId, event) {
  event.stopPropagation();
  if (!confirm("Are you sure you want to unlink this account? All local email cache will be deleted.")) return;
  try {
    await fetch(`${API}/api/accounts/delete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: accountId })
    });
    if (currentAccount === accountId) currentAccount = null;
    loadAccounts();
  } catch (e) {
    console.error("Error deleting account:", e);
  }
}
