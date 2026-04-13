'use strict';

// ── State ────────────────────────────────────────────────────────────────────
const State = {
  page: 'dashboard',
  license: null,
  realtimeActive: false,
  rtFeed: [],
  rtThreats: [],
  currentThreats: [],
  scanning: false,
  stats: null,
  defenderStatus: null,
  theme: 'dark',
  exclusions: [],
};

// ── Utils ─────────────────────────────────────────────────────────────────────
function escHtml(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function fmtDate(d) { if (!d) return '—'; return new Date(d).toLocaleString('fr-FR'); }
function severityClass(s) {
  switch((s||'').toUpperCase()) {
    case 'CRITICAL': return 'critical';
    case 'HIGH':     return 'high';
    case 'MEDIUM':   return 'medium';
    default:         return '';
  }
}
function severityIcon(s) {
  switch((s||'').toUpperCase()) {
    case 'CRITICAL': return '🚨';
    case 'HIGH':     return '⚠️';
    case 'MEDIUM':   return '🔔';
    default:         return 'ℹ️';
  }
}
function severityBadge(s) {
  switch((s||'').toUpperCase()) {
    case 'CRITICAL': return '<span class="badge badge-red">CRITIQUE</span>';
    case 'HIGH':     return '<span class="badge badge-amber">ÉLEVÉ</span>';
    case 'MEDIUM':   return '<span class="badge badge-blue">MOYEN</span>';
    default:         return '<span class="badge badge-gray">INFO</span>';
  }
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const c = document.getElementById('toasts');
  if (!c) return;
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.innerHTML = `${type==='error'?'🚨':type==='success'?'✅':type==='warn'?'⚠️':'ℹ️'} ${escHtml(msg)}`;
  c.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// ── Shell ─────────────────────────────────────────────────────────────────────
function renderShell() {
  document.getElementById('app').innerHTML = `
    <div class="titlebar">
      <div class="tl-group">
        <button class="tl r" onclick="gp.winClose()"></button>
        <button class="tl y" onclick="gp.winMin()"></button>
        <button class="tl g" onclick="gp.winMax()"></button>
      </div>
      <div class="title-center">
        <span>🛡️ GuardPilot Pro</span>
        <span class="title-badge">ANTIVIRUS</span>
        <span class="title-rt ${State.realtimeActive?'':'off'}" id="rt-status">
          <span class="rt-dot ${State.realtimeActive?'':'off'}"></span>
          ${State.realtimeActive ? 'Protection active' : 'Protection inactive'}
        </span>
      </div>
      <div style="display:flex;align-items:center;gap:8px;-webkit-app-region:no-drag">
        <button class="btn btn-ghost btn-sm" style="height:24px;padding:0 8px;font-size:11px" onclick="toggleTheme()" title="Basculer thème">${State.theme==='dark'?'☀️':'🌙'}</button>
        <span style="font-size:10px;color:var(--text3)">SOS INFO LUDO</span>
      </div>
    </div>
    <div class="layout">
      <div class="sidebar">
        <div class="sb-logo">
          <div class="sb-logo-icon">🛡️</div>
          <div>
            <div class="sb-logo-name">GuardPilot <span class="pro-badge">PRO</span></div>
            <div class="sb-logo-sub">Sécurité nouvelle génération</div>
          </div>
        </div>
        <div class="sidebar-scroll" id="sb-scroll">
          ${renderSidebar()}
        </div>
        <div class="sb-bottom">
          <div style="font-size:11px;color:var(--text2);font-weight:600" id="sb-rt-btn">
            ${State.realtimeActive
              ? `<button class="btn btn-danger btn-sm" style="width:100%" onclick="toggleRealtime()">⏹ Désactiver protection</button>`
              : `<button class="btn btn-success btn-sm" style="width:100%" onclick="toggleRealtime()">▶ Activer protection</button>`}
          </div>
          <div class="sb-ver">v1.0.0 — SOS INFO LUDO</div>
        </div>
      </div>
      <div class="main-content">
        <div id="content"><div class="content"><div class="loading"><div class="spinner"></div></div></div></div>
      </div>
    </div>
    <div class="toast-container" id="toasts"></div>
  `;
}

const PAGES = [
  { id:'dashboard',    icon:'🏠', label:'Tableau de bord',       section:'PRINCIPAL' },
  { id:'scan',         icon:'🔍', label:'Scanner',               section:'PROTECTION' },
  { id:'realtime',     icon:'⚡', label:'Protection temps réel', section:'PROTECTION' },
  { id:'defender',     icon:'🛡️', label:'Signatures GuardPilot',  section:'PROTECTION' },
  { id:'registry',     icon:'📋', label:'Registre Windows',      section:'ANALYSE' },
  { id:'processes',    icon:'⚙️', label:'Processus',             section:'ANALYSE' },
  { id:'network',      icon:'🌐', label:'Réseau',                section:'ANALYSE' },
  { id:'tasks',        icon:'📆', label:'Tâches planifiées',     section:'ANALYSE' },
  { id:'services',     icon:'🔧', label:'Services Windows',      section:'ANALYSE' },
  { id:'extensions',   icon:'🧩', label:'Extensions navigateurs',section:'ANALYSE' },
  { id:'advanced',     icon:'🔬', label:'Audit avancé',          section:'ANALYSE' },
  { id:'vulns',        icon:'🔐', label:'Vulnérabilités',        section:'ANALYSE' },
  { id:'quarantine',   icon:'🔒', label:'Quarantaine',           section:'GESTION', badge:'qtCount' },
  { id:'history',      icon:'📅', label:'Historique scans',      section:'GESTION' },
  { id:'actionlog',    icon:'📝', label:'Journal des actions',   section:'GESTION' },
  { id:'stats',        icon:'📊', label:'Statistiques',          section:'GESTION' },
  { id:'exclusions',   icon:'🚫', label:'Exclusions',            section:'PARAMÈTRES' },
  { id:'schedule',     icon:'⏰', label:'Scans planifiés',       section:'PARAMÈTRES' },
  { id:'license',      icon:'🔑', label:'Licence',               section:'COMPTE' },
];

function renderSidebar() {
  let lastSection = '';
  return PAGES.map(p => {
    let out = '';
    if (p.section !== lastSection) {
      out += `<div class="sb-section">${p.section}</div>`;
      lastSection = p.section;
    }
    const count = p.badge === 'qtCount' ? State.rtThreats.length : 0;
    out += `
      <div class="sb-item ${State.page===p.id?'active':''}" onclick="navTo('${p.id}')">
        <span class="ico">${p.icon}</span>
        <span>${p.label}</span>
        ${count > 0 ? `<span class="badge-count">${count}</span>` : ''}
      </div>
    `;
    return out;
  }).join('');
}

function navTo(page) {
  State.page = page;
  const sb = document.getElementById('sb-scroll');
  if (sb) sb.innerHTML = renderSidebar();
  renderPage(page);
}

function setContent(html) {
  document.getElementById('content').innerHTML = `<div class="content">${html}</div>`;
}

function updateRtStatus() {
  const el = document.getElementById('rt-status');
  if (el) el.innerHTML = `<span class="rt-dot ${State.realtimeActive?'':'off'}"></span>${State.realtimeActive?'Protection active':'Protection inactive'}`;
  el?.className && (el.className = `title-rt ${State.realtimeActive?'':'off'}`);
  const btn = document.getElementById('sb-rt-btn');
  if (btn) btn.innerHTML = State.realtimeActive
    ? `<button class="btn btn-danger btn-sm" style="width:100%" onclick="toggleRealtime()">⏹ Désactiver protection</button>`
    : `<button class="btn btn-success btn-sm" style="width:100%" onclick="toggleRealtime()">▶ Activer protection</button>`;
}

// ── Realtime control ──────────────────────────────────────────────────────────
async function toggleRealtime() {
  if (State.realtimeActive) {
    await gp.stopRealtime();
    State.realtimeActive = false;
    toast('Protection temps réel désactivée', 'warn');
  } else {
    await gp.startRealtime();
    State.realtimeActive = true;
    toast('Protection temps réel activée', 'success');
  }
  updateRtStatus();
  if (State.page === 'realtime') navTo('realtime');
}

// ── Pages ─────────────────────────────────────────────────────────────────────
function renderPage(page) {
  switch(page) {
    case 'dashboard':  renderDashboard(); break;
    case 'scan':       renderScan(); break;
    case 'realtime':   renderRealtimePage(); break;
    case 'defender':   renderDefender(); break;
    case 'registry':   renderRegistry(); break;
    case 'processes':  renderProcesses(); break;
    case 'network':    renderNetwork(); break;
    case 'tasks':      renderTasks(); break;
    case 'services':   renderServices(); break;
    case 'extensions': renderExtensions(); break;
    case 'advanced':   renderAdvanced(); break;
    case 'vulns':      renderVulns(); break;
    case 'quarantine': renderQuarantine(); break;
    case 'history':    renderHistory(); break;
    case 'actionlog':  renderActionLog(); break;
    case 'stats':      renderStats(); break;
    case 'exclusions': renderExclusions(); break;
    case 'schedule':   renderSchedule(); break;
    case 'license':    renderLicense(); break;
    default: renderDashboard();
  }
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function renderDashboard() {
  setContent(`<div class="loading"><div class="spinner"></div>Analyse de sécurité...</div>`);
  const [stats, lastScan, rtStatus, sigInfo] = await Promise.all([
    gp.getStats(), gp.getLastScan(), gp.getRealtimeStatus(), gp.getSignaturesInfo()
  ]);
  State.stats = stats;
  State.realtimeActive = rtStatus.active;
  updateRtStatus();

  const rtOk = rtStatus.active;
  const lastThreatCount = lastScan?.count || 0;

  // Score calculation — GuardPilot engine only, no Windows Defender
  let score = 100;
  if (!rtOk) score -= 35;
  if (lastThreatCount > 0) score -= Math.min(40, lastThreatCount * 5);
  score = Math.max(0, score);
  const scoreColor = score >= 80 ? '#10B981' : score >= 50 ? '#F59E0B' : '#EF4444';
  const scoreLabel = score >= 80 ? 'PROTÉGÉ' : score >= 50 ? 'ATTENTION' : 'DANGER';
  const circumference = 2 * Math.PI * 50;
  const dashOffset = circumference - (score / 100) * circumference;

  setContent(`
    <div class="topbar">
      <h1>🏠 Tableau de bord sécurité</h1>
      <div class="topbar-actions">
        <button class="btn btn-primary" onclick="navTo('scan')">🔍 Lancer un scan</button>
        <button class="btn btn-ghost" onclick="exportPDFReport()">📄 Rapport PDF</button>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:auto 1fr;gap:20px;margin-bottom:20px;align-items:center">
      <div style="display:flex;flex-direction:column;align-items:center;gap:8px">
        <div class="score-ring">
          <svg width="130" height="130" viewBox="0 0 120 120" style="color:${scoreColor}">
            <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="10"/>
            <circle cx="60" cy="60" r="50" fill="none" stroke="${scoreColor}" stroke-width="10"
              stroke-dasharray="${circumference}" stroke-dashoffset="${dashOffset}"
              stroke-linecap="round"/>
          </svg>
          <div class="score-ring-val">
            <span class="score-num" style="color:${scoreColor}">${score}</span>
            <span class="score-lbl" style="color:${scoreColor}">${scoreLabel}</span>
          </div>
        </div>
        <div style="font-size:11px;color:var(--text3);text-align:center">Score de sécurité</div>
      </div>
      <div class="status-grid">
        <div class="status-card" style="--card-color:${rtOk?'#10B981':'#EF4444'}">
          <div class="sc-icon">${rtOk?'🛡️':'🔓'}</div>
          <div class="sc-label">Protection temps réel</div>
          <div class="sc-value" style="color:${rtOk?'var(--green)':'var(--red)'};font-size:16px">${rtOk?'Active':'Inactive'}</div>
          <div class="sc-sub">${rtOk?'Surveillance en cours':'Cliquez pour activer'}</div>
        </div>
        <div class="status-card" style="--card-color:#8B5CF6">
          <div class="sc-icon">🛡️</div>
          <div class="sc-label">Moteur GuardPilot</div>
          <div class="sc-value" style="color:var(--purple, #8B5CF6);font-size:13px">${sigInfo?.version || '—'}</div>
          <div class="sc-sub">${sigInfo?.hashCount ?? '—'} signatures chargées</div>
        </div>
        <div class="status-card" style="--card-color:#3B82F6">
          <div class="sc-icon">🔍</div>
          <div class="sc-label">Dernier scan</div>
          <div class="sc-value" style="font-size:13px;color:var(--text)">${lastScan ? fmtDate(lastScan.date).split(' ')[0] : '—'}</div>
          <div class="sc-sub">${lastScan ? `${lastScan.count} menace(s)` : 'Aucun scan effectué'}</div>
        </div>
        <div class="status-card" style="--card-color:${State.rtThreats.length>0?'#EF4444':'#10B981'}">
          <div class="sc-icon">${State.rtThreats.length>0?'⚠️':'✅'}</div>
          <div class="sc-label">Alertes actives</div>
          <div class="sc-value" style="color:${State.rtThreats.length>0?'var(--red)':'var(--green)'}">
            ${State.rtThreats.length}
          </div>
          <div class="sc-sub">${State.rtThreats.length>0?'Menaces détectées':'Système propre'}</div>
        </div>
      </div>
    </div>

    <div class="scan-grid">
      <div class="scan-card" onclick="startQuickScan()" style="--scan-color:rgba(59,130,246,0.3)">
        <span class="scan-card-icon">⚡</span>
        <div class="scan-card-name">Scan rapide</div>
        <div class="scan-card-desc">Zones critiques, démarrage, temp</div>
      </div>
      <div class="scan-card" onclick="navTo('scan')" style="--scan-color:rgba(245,158,11,0.3)">
        <span class="scan-card-icon">🔍</span>
        <div class="scan-card-name">Scan complet</div>
        <div class="scan-card-desc">Analyse de tous les disques</div>
      </div>
      <div class="scan-card" onclick="navTo('vulns')" style="--scan-color:rgba(16,185,129,0.3)">
        <span class="scan-card-icon">🔐</span>
        <div class="scan-card-name">Vérification sécurité</div>
        <div class="scan-card-desc">UAC, pare-feu, mises à jour</div>
      </div>
    </div>

    ${State.rtThreats.length > 0 ? `
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">🚨 Alertes récentes</div>
          <span class="badge badge-red">${State.rtThreats.length}</span>
        </div>
        <div class="threat-list">
          ${State.rtThreats.slice(0,5).map(t => renderThreatItem(t)).join('')}
        </div>
      </div>
    ` : `
      <div class="panel">
        <div style="padding:32px;text-align:center;color:var(--green);font-size:14px;font-weight:700">
          ✅ Aucune menace active détectée
        </div>
      </div>
    `}
  `);
}

// ── Scanner page ──────────────────────────────────────────────────────────────
function renderScan() {
  setContent(`
    <div class="topbar"><h1>🔍 Scanner</h1></div>
    <div class="scan-grid">
      <div class="scan-card" onclick="startQuickScan()" style="--scan-color:rgba(59,130,246,0.3)">
        <span class="scan-card-icon">⚡</span>
        <div class="scan-card-name">Scan rapide</div>
        <div class="scan-card-desc">Temp, Downloads, Démarrage<br><strong>~1-2 minutes</strong></div>
      </div>
      <div class="scan-card" onclick="startFullScan()" style="--scan-color:rgba(245,158,11,0.3)">
        <span class="scan-card-icon">🌐</span>
        <div class="scan-card-name">Scan complet</div>
        <div class="scan-card-desc">Tous les disques détectés<br><strong>~15-30 minutes</strong></div>
      </div>
      <div class="scan-card" onclick="startCustomScan()" style="--scan-color:rgba(139,92,246,0.3)">
        <span class="scan-card-icon">📂</span>
        <div class="scan-card-name">Scan personnalisé</div>
        <div class="scan-card-desc">Choisissez un dossier spécifique</div>
      </div>
    </div>
    <div id="scan-results"></div>
  `);
}

async function exportPDFReport() {
  const stats = await gp.getStats();
  await gp.exportPDF({ threats: State.currentThreats || [], stats });
}
async function exportWordReport() {
  const stats = await gp.getStats();
  await gp.exportWord({ threats: State.currentThreats || [], stats });
}

async function startQuickScan() {
  if (State.scanning) return;
  State.scanning = true;
  navTo('scan');
  await new Promise(r => setTimeout(r, 50));
  const results = document.getElementById('scan-results');
  if (!results) return;
  results.innerHTML = `
    <div class="panel">
      <div class="panel-header"><div class="panel-title">⚡ Scan rapide en cours...</div></div>
      <div class="scan-progress">
        <div class="progress-bar-wrap"><div class="progress-bar" style="width:100%"></div></div>
        <div class="progress-file" id="scan-file">Initialisation...</div>
      </div>
    </div>
  `;
  gp.removeAllListeners('scan-progress');
  gp.onScanProgress((p) => {
    const el = document.getElementById('scan-file');
    if (el) el.textContent = p.path ? `Analyse: ${p.path}` : 'Scan en cours...';
  });
  try {
    const res = await gp.quickScan();
    State.scanning = false;
    State.currentThreats = res.threats || [];
    if (res.threats.length > 0) State.rtThreats.push(...res.threats);
    showScanResults(res.threats, 'rapide');
    promptAutoPDF(res.threats || []);
  } catch(e) {
    State.scanning = false;
    toast('Erreur lors du scan', 'error');
  }
}

async function startFullScan() {
  if (State.scanning) return;
  State.scanning = true;
  navTo('scan');
  await new Promise(r => setTimeout(r, 50));
  const results = document.getElementById('scan-results');
  if (!results) return;
  results.innerHTML = `
    <div class="panel">
      <div class="panel-header"><div class="panel-title">🌐 Scan complet en cours... (peut prendre plusieurs minutes)</div></div>
      <div class="scan-progress">
        <div class="progress-bar-wrap"><div class="progress-bar" style="width:100%"></div></div>
        <div class="progress-file" id="scan-file">Initialisation...</div>
      </div>
    </div>
  `;
  gp.removeAllListeners('scan-progress');
  gp.onScanProgress((p) => {
    const el = document.getElementById('scan-file');
    if (el) el.textContent = p.path ? `Analyse: ${p.path}` : 'Scan en cours...';
  });
  try {
    const res = await gp.fullScan();
    State.scanning = false;
    State.currentThreats = res.threats || [];
    if (res.threats.length > 0) State.rtThreats.push(...res.threats);
    showScanResults(res.threats, 'complet');
    promptAutoPDF(res.threats || []);
  } catch(e) {
    State.scanning = false;
    toast('Erreur lors du scan', 'error');
  }
}

async function startCustomScan() {
  const folder = await gp.chooseScanFolder();
  if (!folder) return;
  if (State.scanning) return;
  State.scanning = true;
  navTo('scan');
  await new Promise(r => setTimeout(r, 50));
  const results = document.getElementById('scan-results');
  if (!results) return;
  results.innerHTML = `
    <div class="panel">
      <div class="panel-header"><div class="panel-title">📂 Scan de "${escHtml(folder)}"...</div></div>
      <div class="scan-progress">
        <div class="progress-bar-wrap"><div class="progress-bar" style="width:100%"></div></div>
        <div class="progress-file" id="scan-file">Initialisation...</div>
      </div>
    </div>
  `;
  gp.removeAllListeners('scan-progress');
  gp.onScanProgress((p) => {
    const el = document.getElementById('scan-file');
    if (el) el.textContent = p.path ? `Analyse: ${p.path}` : 'Scan en cours...';
  });
  try {
    const res = await gp.customScan(folder);
    State.scanning = false;
    State.currentThreats = res.threats || [];
    showScanResults(res.threats, 'personnalisé');
  } catch(e) {
    State.scanning = false;
    toast('Erreur lors du scan', 'error');
  }
}

function showScanResults(threats, type) {
  const results = document.getElementById('scan-results');
  if (!results) return;
  if (threats.length === 0) {
    results.innerHTML = `
      <div class="panel">
        <div style="padding:40px;text-align:center">
          <div style="font-size:48px;margin-bottom:12px">✅</div>
          <div style="font-size:16px;font-weight:800;color:var(--green);margin-bottom:6px">Aucune menace détectée</div>
          <div style="font-size:12px;color:var(--text3)">Le scan ${type} n'a révélé aucun fichier malveillant</div>
        </div>
      </div>
    `;
    toast('Scan terminé — Aucune menace détectée', 'success');
    return;
  }
  const critical = threats.filter(t => t.severity === 'CRITICAL').length;
  const high = threats.filter(t => t.severity === 'HIGH').length;
  results.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🚨 Résultats — ${threats.length} menace(s) détectée(s)</div>
        <div style="display:flex;gap:6px">
          ${critical>0?`<span class="badge badge-red">${critical} CRITIQUE(S)</span>`:''}
          ${high>0?`<span class="badge badge-amber">${high} ÉLEVÉ(S)</span>`:''}
          <button class="btn btn-ghost btn-sm" onclick="quarantineAll()">🔒 Tout mettre en quarantaine</button>
          <button class="btn btn-ghost btn-sm" onclick="exportPDFReport()">📄 PDF</button>
          <button class="btn btn-ghost btn-sm" onclick="exportWordReport()">📝 Word</button>
          <button class="btn btn-primary btn-sm" onclick="renderClientReport()">👁 Vue client</button>
        </div>
      </div>
      <div class="threat-list">
        ${threats.map(t => renderThreatItem(t, true)).join('')}
      </div>
    </div>
  `;
  toast(`⚠️ ${threats.length} menace(s) détectée(s) !`, 'error');
}

function riskScore(t) {
  const base = { CRITICAL:90, HIGH:65, MEDIUM:35 }[(t.severity||'').toUpperCase()] || 15;
  return Math.min(100, base + (t.type === 'KNOWN_MALWARE' || t.type === 'RANSOMWARE' ? 10 : 0));
}
function riskColor(score) {
  return score >= 80 ? 'var(--red)' : score >= 50 ? 'var(--amber)' : 'var(--blue)';
}
function fSafe(s) { return escHtml((s||'').replace(/'/g,"&#39;")); }

function renderThreatItem(t, withActions = false) {
  const score = riskScore(t);
  return `
    <div class="threat-item ${severityClass(t.severity)}">
      <span class="threat-icon">${severityIcon(t.severity)}</span>
      <div class="threat-info">
        <div class="threat-desc">${severityBadge(t.severity)} ${escHtml(t.desc||'')}</div>
        <div class="threat-file">${escHtml(t.file||'')}</div>
        ${t.date ? `<div style="font-size:10px;color:var(--text3);margin-top:2px">${fmtDate(t.date)}</div>` : ''}
      </div>
      <div style="display:flex;flex-direction:column;align-items:center;gap:2px;flex-shrink:0;margin:0 8px;min-width:36px">
        <div style="font-size:16px;font-weight:900;color:${riskColor(score)}">${score}</div>
        <div style="font-size:9px;color:var(--text3)">RISQUE</div>
      </div>
      ${withActions && t.file ? `
        <div class="threat-actions">
          <button class="btn btn-danger btn-sm" onclick="quarantineOne('${fSafe(t.file)}')">🔒 Quarantaine</button>
          <button class="btn btn-ghost btn-sm" style="color:var(--red);border-color:var(--red-b)" onclick="deleteFileDirect('${fSafe(t.file)}')">🗑 Supprimer</button>
          ${t.canFix ? `<button class="btn btn-ghost btn-sm" onclick="fixThreat(${JSON.stringify(JSON.stringify(t)).slice(1,-1)})">🔧 Corriger</button>` : ''}
        </div>
      ` : ''}
    </div>
  `;
}

async function quarantineOne(filePath) {
  const res = await gp.quarantineFile(filePath);
  if (res.success) {
    toast('Fichier mis en quarantaine', 'success');
    await gp.logAction({ type: 'quarantine', desc: 'Mis en quarantaine', file: filePath });
  } else toast(res.error || 'Erreur', 'error');
}

async function quarantineAll() {
  let count = 0;
  for (const t of State.currentThreats) {
    if (t.file) {
      const res = await gp.quarantineFile(t.file);
      if (res.success) { count++; await gp.logAction({ type: 'quarantine', desc: t.desc || 'Mis en quarantaine', file: t.file }); }
    }
  }
  toast(`${count} fichier(s) mis en quarantaine`, 'success');
}

async function fixThreat(t) {
  if (t.type === 'SUSPICIOUS_AUTORUN' && t.fixKey && t.fixName) {
    const res = await gp.removeAutorun({ key: t.fixKey, name: t.fixName });
    if (res.success) {
      toast('Entrée de démarrage supprimée', 'success');
      await gp.logAction({ type: 'fix', desc: `Autorun supprimé: ${t.fixName}`, file: t.file });
    } else toast(res.error || 'Erreur', 'error');
  }
}

async function deleteFileDirect(filePath) {
  if (!confirm(`Supprimer définitivement ce fichier ?\n\n${filePath}\n\nCette action est irréversible.`)) return;
  const res = await gp.deleteFile(filePath);
  if (res.success) {
    toast('Fichier supprimé définitivement', 'success');
    await gp.logAction({ type: 'delete', desc: `Fichier supprimé`, file: filePath });
    State.currentThreats = State.currentThreats.filter(t => t.file !== filePath);
  } else toast(res.error || 'Impossible de supprimer', 'error');
}

// ── Drag & drop file analysis ─────────────────────────────────────────────────
function initDragDrop() {
  document.addEventListener('dragover', (e) => {
    e.preventDefault();
    const zone = document.getElementById('drop-zone');
    if (zone) zone.classList.add('drag-over');
  });
  document.addEventListener('dragleave', (e) => {
    if (!e.relatedTarget || e.relatedTarget === document.documentElement) {
      const zone = document.getElementById('drop-zone');
      if (zone) zone.classList.remove('drag-over');
    }
  });
  document.addEventListener('drop', async (e) => {
    e.preventDefault();
    const zone = document.getElementById('drop-zone');
    if (zone) zone.classList.remove('drag-over');
    const files = Array.from(e.dataTransfer.files);
    if (!files.length) return;
    navTo('scan');
    await new Promise(r => setTimeout(r, 50));
    const results = document.getElementById('scan-results');
    if (!results) return;
    results.innerHTML = `<div class="panel"><div class="panel-header"><div class="panel-title">📂 Analyse de ${files.length} fichier(s)...</div></div><div style="padding:16px;color:var(--text3)">Analyse en cours...</div></div>`;
    const allThreats = [];
    for (const file of files) {
      const res = await gp.analyzeFile(file.path);
      allThreats.push(...(res.threats || []));
    }
    State.currentThreats = allThreats;
    showScanResults(allThreats, 'fichier(s) glissé(s)');
  });
}

// ── Theme toggle ──────────────────────────────────────────────────────────────
function applyTheme(theme) {
  State.theme = theme;
  document.documentElement.setAttribute('data-theme', theme);
}

async function toggleTheme() {
  const newTheme = State.theme === 'dark' ? 'light' : 'dark';
  applyTheme(newTheme);
  await gp.setPref('theme', newTheme);
  // Re-render shell to update icon
  const wasPage = State.page;
  renderShell();
  navTo(wasPage);
}

// ── Auto PDF prompt after scan ────────────────────────────────────────────────
async function promptAutoPDF(threats) {
  if (threats.length === 0) return;
  await new Promise(r => setTimeout(r, 800));
  if (confirm(`${threats.length} menace(s) trouvée(s). Générer un rapport PDF pour le client ?`)) {
    await exportPDFReport();
  }
}

// ── Client report mode ────────────────────────────────────────────────────────
function renderClientReport() {
  const threats = State.currentThreats || [];
  const critical = threats.filter(t => (t.severity||'').toUpperCase() === 'CRITICAL').length;
  const high = threats.filter(t => (t.severity||'').toUpperCase() === 'HIGH').length;
  const statusColor = threats.length === 0 ? '#10B981' : critical > 0 ? '#EF4444' : '#F59E0B';
  const statusMsg = threats.length === 0 ? 'Votre ordinateur est sain ✅' : `${threats.length} problème(s) de sécurité détecté(s)`;

  const win = window.open('', '_blank');
  win.document.write(`<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
  <title>Rapport GuardPilot — S.O.S INFO LUDO</title>
  <style>
    body{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:40px;background:#f5f7fa;color:#1F2937}
    .header{background:linear-gradient(135deg,#0A0F1E,#1E3A5F);color:#fff;padding:30px 40px;border-radius:12px;margin-bottom:24px}
    .logo{font-size:22px;font-weight:800}.sub{font-size:12px;color:#94A3B8;margin-top:4px}
    .status-box{background:#fff;border-radius:12px;padding:30px;text-align:center;margin-bottom:24px;box-shadow:0 2px 12px rgba(0,0,0,0.08)}
    .status-num{font-size:64px;font-weight:900;color:${statusColor}}
    .status-msg{font-size:18px;font-weight:700;color:#1F2937;margin-top:8px}
    .threat-row{background:#fff;border-radius:8px;padding:14px 18px;margin-bottom:8px;border-left:4px solid ${statusColor};box-shadow:0 1px 4px rgba(0,0,0,0.06)}
    .threat-type{font-size:11px;font-weight:700;color:#6B7280;text-transform:uppercase}
    .threat-desc{font-size:13px;font-weight:600;color:#1F2937;margin:4px 0}
    .footer{text-align:center;font-size:12px;color:#9CA3AF;margin-top:32px}
    @media print{body{background:#fff}}
  </style></head><body>
  <div class="header">
    <div class="logo">🛡️ GuardPilot Pro — Rapport Sécurité</div>
    <div class="sub">S.O.S INFO LUDO — ${new Date().toLocaleDateString('fr-FR', {day:'numeric',month:'long',year:'numeric'})}</div>
  </div>
  <div class="status-box">
    <div class="status-num">${threats.length}</div>
    <div class="status-msg">${statusMsg}</div>
  </div>
  ${threats.length > 0 ? `<div>${threats.map(t=>`
    <div class="threat-row">
      <div class="threat-type">${escHtml(t.type||'')} — ${escHtml(t.severity||'')}</div>
      <div class="threat-desc">${escHtml(t.desc||'')}</div>
      <div style="font-size:11px;color:#9CA3AF;margin-top:2px;font-family:monospace">${escHtml(t.file||'')}</div>
    </div>`).join('')}</div>` : ''}
  <div class="footer">Rapport généré par GuardPilot Pro — S.O.S INFO LUDO — Ludovic Tourniquet</div>
  <script>window.print()</script></body></html>`);
  win.document.close();
}

// ── Exclusions page ───────────────────────────────────────────────────────────
async function renderExclusions() {
  const excl = await gp.getExclusions();
  State.exclusions = excl;
  setContent(`
    <div class="topbar">
      <h1>🚫 Exclusions</h1>
      <div class="topbar-actions">
        <button class="btn btn-primary" onclick="addExclusion()">➕ Ajouter un dossier</button>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🚫 Dossiers et fichiers exclus des scans</div>
        <span class="badge badge-blue">${excl.length}</span>
      </div>
      <div style="padding:10px 0;font-size:12px;color:var(--text3);padding:12px 18px">
        Ces chemins seront ignorés lors des scans — utile pour éviter les faux positifs sur les logiciels légitimes de vos clients.
      </div>
      ${excl.length === 0
        ? '<div style="padding:32px;text-align:center;color:var(--text3)">Aucune exclusion configurée</div>'
        : `<table class="data-table">
            <thead><tr><th>Chemin exclu</th><th>Action</th></tr></thead>
            <tbody>
              ${excl.map(p => `
                <tr>
                  <td style="font-family:var(--font-mono);font-size:11px">${escHtml(p)}</td>
                  <td><button class="btn btn-danger btn-sm" onclick="removeExclusion('${fSafe(p)}')">✕ Retirer</button></td>
                </tr>`).join('')}
            </tbody>
          </table>`}
    </div>
  `);
}

async function addExclusion() {
  const p = await gp.chooseExclusionPath();
  if (!p) return;
  await gp.addExclusion(p);
  toast(`Exclusion ajoutée : ${p}`, 'success');
  renderExclusions();
}

async function removeExclusion(p) {
  await gp.removeExclusion(p);
  toast('Exclusion retirée', 'info');
  renderExclusions();
}

// ── Action log page ───────────────────────────────────────────────────────────
async function renderActionLog() {
  const log = await gp.getActionLog();
  const icons = { quarantine:'🔒', delete:'🗑', fix:'🔧', restore:'↩' };
  setContent(`
    <div class="topbar">
      <h1>📝 Journal des actions</h1>
      <button class="btn btn-ghost" onclick="gp.clearActionLog().then(()=>renderActionLog())">🗑 Effacer</button>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Toutes les actions effectuées</div>
        <span class="badge badge-blue">${log.length}</span>
      </div>
      ${log.length === 0
        ? '<div style="padding:32px;text-align:center;color:var(--text3)">Aucune action enregistrée</div>'
        : `<table class="data-table">
            <thead><tr><th>Date</th><th>Action</th><th>Description</th><th>Fichier</th></tr></thead>
            <tbody>
              ${log.map(a => `
                <tr>
                  <td style="white-space:nowrap;font-size:11px">${fmtDate(a.date)}</td>
                  <td>${icons[a.type]||'•'} ${escHtml(a.type||'')}</td>
                  <td>${escHtml(a.desc||'')}</td>
                  <td style="font-family:var(--font-mono);font-size:10px;color:var(--text3);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(a.file||'—')}</td>
                </tr>`).join('')}
            </tbody>
          </table>`}
    </div>
  `);
}

// ── Stats page ────────────────────────────────────────────────────────────────
async function renderStats() {
  setContent(`<div class="loading"><div class="spinner"></div>Calcul des statistiques...</div>`);
  const s = await gp.getStats();

  // Build monthly chart data from history
  const months = {};
  (s.history || []).forEach(h => {
    const d = new Date(h.date);
    const key = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`;
    if (!months[key]) months[key] = { scans:0, threats:0 };
    months[key].scans++;
    months[key].threats += typeof h.threats === 'number' ? h.threats : 0;
  });
  const monthKeys = Object.keys(months).sort().slice(-6);
  const maxScans = Math.max(1, ...monthKeys.map(k => months[k].scans));

  setContent(`
    <div class="topbar"><h1>📊 Statistiques</h1></div>
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px">
      <div class="status-card" style="--card-color:#2563EB">
        <div class="sc-icon">🔍</div>
        <div class="sc-label">Total scans</div>
        <div class="sc-value" style="color:var(--blue)">${s.totalScans}</div>
        <div class="sc-sub">${s.scansThisMonth} ce mois-ci</div>
      </div>
      <div class="status-card" style="--card-color:#EF4444">
        <div class="sc-icon">🦠</div>
        <div class="sc-label">Menaces trouvées</div>
        <div class="sc-value" style="color:var(--red)">${s.threatsFound}</div>
        <div class="sc-sub">${s.threatsThisMonth} ce mois-ci</div>
      </div>
      <div class="status-card" style="--card-color:#10B981">
        <div class="sc-icon">🔒</div>
        <div class="sc-label">En quarantaine</div>
        <div class="sc-value" style="color:var(--green)">${s.quarantined}</div>
        <div class="sc-sub">${s.actionsTotal} actions totales</div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><div class="panel-title">📈 Activité des 6 derniers mois</div></div>
      <div style="padding:20px">
        ${monthKeys.length === 0
          ? '<div style="text-align:center;color:var(--text3);padding:20px">Pas encore de données</div>'
          : monthKeys.map(k => `
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">
              <div style="font-size:11px;color:var(--text3);width:55px;flex-shrink:0">${k}</div>
              <div style="flex:1;background:var(--bg);border-radius:4px;height:20px;overflow:hidden">
                <div style="height:100%;width:${Math.round((months[k].scans/maxScans)*100)}%;background:linear-gradient(90deg,var(--blue),var(--cyan));border-radius:4px;transition:width .5s"></div>
              </div>
              <div style="font-size:11px;color:var(--text2);width:80px;flex-shrink:0">${months[k].scans} scan(s)</div>
              <div style="font-size:11px;color:var(--red);width:60px;flex-shrink:0">${months[k].threats} menace(s)</div>
            </div>`).join('')}
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><div class="panel-title">📅 Dernier scan</div></div>
      <div style="padding:16px 20px;font-size:13px;color:var(--text2)">
        ${s.lastScan ? fmtDate(s.lastScan) : 'Aucun scan effectué'}
      </div>
    </div>
  `);
}

// ── Scheduled scans page ──────────────────────────────────────────────────────
async function renderSchedule() {
  const tasks = await gp.getScheduledScans();
  setContent(`
    <div class="topbar">
      <h1>⏰ Scans planifiés</h1>
    </div>
    <div class="panel">
      <div class="panel-header"><div class="panel-title">Planifier un scan automatique</div></div>
      <div style="padding:20px;display:flex;flex-direction:column;gap:14px">
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:10px;align-items:end">
          <div>
            <label style="font-size:11px;color:var(--text3);display:block;margin-bottom:4px">TYPE DE SCAN</label>
            <select id="sch-type" class="input-field">
              <option value="quick">Scan rapide</option>
              <option value="full">Scan complet</option>
            </select>
          </div>
          <div>
            <label style="font-size:11px;color:var(--text3);display:block;margin-bottom:4px">FRÉQUENCE</label>
            <select id="sch-freq" class="input-field" onchange="updateSchDay()">
              <option value="daily">Tous les jours</option>
              <option value="weekly">Hebdomadaire</option>
            </select>
          </div>
          <div id="sch-day-wrap">
            <label style="font-size:11px;color:var(--text3);display:block;margin-bottom:4px">HEURE</label>
            <input type="time" id="sch-time" value="08:00" class="input-field">
          </div>
          <button class="btn btn-primary" onclick="scheduleScan()">➕ Planifier</button>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">⏰ Tâches planifiées actives</div>
        <span class="badge badge-blue">${tasks.length}</span>
      </div>
      ${tasks.length === 0
        ? '<div style="padding:32px;text-align:center;color:var(--text3)">Aucun scan planifié</div>'
        : `<table class="data-table">
            <thead><tr><th>Tâche</th><th>État</th><th>Action</th></tr></thead>
            <tbody>
              ${tasks.map(t => `
                <tr>
                  <td>${escHtml(t.TaskName||'')}</td>
                  <td><span class="badge ${t.State===3?'badge-green':'badge-gray'}">${t.State===3?'Actif':'Inactif'}</span></td>
                  <td><button class="btn btn-danger btn-sm" onclick="unscheduleScan('${fSafe(t.TaskName)}')">✕ Supprimer</button></td>
                </tr>`).join('')}
            </tbody>
          </table>`}
    </div>
  `);
}

async function scheduleScan() {
  const scanType = document.getElementById('sch-type')?.value || 'quick';
  const freq = document.getElementById('sch-freq')?.value || 'daily';
  const time = document.getElementById('sch-time')?.value || '08:00';
  const trigger = { type: freq, time };
  toast('Planification en cours...', 'info');
  const res = await gp.scheduleScan({ scanType, trigger });
  if (res.success) { toast('Scan planifié avec succès', 'success'); renderSchedule(); }
  else toast(res.error || 'Erreur de planification', 'error');
}

async function unscheduleScan(name) {
  if (!confirm(`Supprimer la tâche planifiée "${name}" ?`)) return;
  const res = await gp.unscheduleScan(name);
  if (res.success) { toast('Tâche supprimée', 'success'); renderSchedule(); }
  else toast('Erreur', 'error');
}

// ── Real-time page ────────────────────────────────────────────────────────────
function renderRealtimePage() {
  setContent(`
    <div class="topbar">
      <h1>⚡ Protection temps réel</h1>
      <div class="topbar-actions">
        <button class="btn ${State.realtimeActive?'btn-danger':'btn-success'}" onclick="toggleRealtime()">
          ${State.realtimeActive ? '⏹ Désactiver' : '▶ Activer'}
        </button>
        <button class="btn btn-ghost" onclick="State.rtFeed=[];State.rtThreats=[];renderRealtimePage()">🗑 Effacer</button>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">
          <span class="rt-dot ${State.realtimeActive?'':'off'}" style="display:inline-block;margin-right:4px"></span>
          ${State.realtimeActive ? 'Surveillance active' : 'Surveillance inactive'}
        </div>
        <span class="badge ${State.realtimeActive?'badge-green':'badge-gray'}">${State.realtimeActive?'EN COURS':'ARRÊTÉ'}</span>
      </div>
      <div style="padding:14px 18px;font-size:12px;color:var(--text2);line-height:1.7">
        La protection temps réel surveille en permanence les dossiers critiques (Temp, Downloads, Desktop, Démarrage)
        et analyse chaque nouveau fichier dès sa création pour détecter les menaces instantanément.
      </div>
    </div>

    ${State.rtThreats.length > 0 ? `
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">🚨 Menaces détectées en temps réel</div>
          <span class="badge badge-red">${State.rtThreats.length}</span>
        </div>
        <div class="threat-list">
          ${State.rtThreats.map(t => renderThreatItem(t, true)).join('')}
        </div>
      </div>
    ` : ''}

    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">📋 Activité récente</div>
        <span style="font-size:11px;color:var(--text3)">${State.rtFeed.length} évènement(s)</span>
      </div>
      <div class="rt-feed" id="rt-feed-container">
        ${State.rtFeed.length === 0
          ? '<div style="padding:20px;text-align:center;color:var(--text3);font-size:12px">Aucune activité enregistrée</div>'
          : State.rtFeed.slice(-50).reverse().map(e => `
            <div class="rt-entry ${e.threat?'threat':'activity'}">
              <span>${e.threat?'🚨':'📄'}</span>
              <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(e.path||e.desc||'')}</span>
              <span style="font-size:10px;color:var(--text3);flex-shrink:0">${new Date(e.time||Date.now()).toLocaleTimeString('fr-FR')}</span>
            </div>
          `).join('')}
      </div>
    </div>
  `);
}

// ── Moteur GuardPilot — Signatures ────────────────────────────────────────────
async function renderDefender() {
  setContent(`<div class="loading"><div class="spinner"></div>Chargement des signatures...</div>`);
  const info = await gp.getSignaturesInfo();

  const isUpToDate = info.updated && info.updated === new Date().toISOString().slice(0,10);
  const statusColor = isUpToDate ? 'var(--green)' : '#F59E0B';
  const statusLabel = isUpToDate ? 'À jour' : 'Mise à jour disponible';

  setContent(`
    <div class="topbar">
      <h1>🛡️ Moteur de détection GuardPilot</h1>
      <div class="topbar-actions">
        <button class="btn btn-primary" onclick="updateGPSigs()" id="btn-update-sigs">🔄 Mettre à jour les signatures</button>
        <button class="btn btn-ghost" onclick="renderDefender()">↺ Actualiser</button>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:20px">
      <div class="status-card" style="--card-color:#2563EB">
        <div class="sc-icon">🛡️</div>
        <div class="sc-label">Version signatures</div>
        <div class="sc-value" style="font-size:14px;color:var(--text)">${escHtml(info.version || '—')}</div>
        <div class="sc-sub">Moteur GuardPilot</div>
      </div>
      <div class="status-card" style="--card-color:${statusColor}">
        <div class="sc-icon">${isUpToDate ? '✅' : '🔔'}</div>
        <div class="sc-label">Statut</div>
        <div class="sc-value" style="color:${statusColor};font-size:14px">${statusLabel}</div>
        <div class="sc-sub">${info.updated ? `Mise à jour : ${info.updated}` : 'Jamais mis à jour'}</div>
      </div>
      <div class="status-card" style="--card-color:#10B981">
        <div class="sc-icon">🦠</div>
        <div class="sc-label">Signatures chargées</div>
        <div class="sc-value" style="color:var(--green)">${info.hashCount || '—'}</div>
        <div class="sc-sub">Hachages malware connus</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><div class="panel-title">ℹ️ À propos du moteur de détection</div></div>
      <div style="padding:20px;font-size:13px;color:var(--text2);line-height:1.8">
        <p>GuardPilot utilise son <strong>propre moteur de détection</strong>, indépendant de Windows Defender.</p>
        <br>
        <p>🔍 <strong>Détection par hash SHA256</strong> — compare chaque fichier aux signatures connues</p>
        <p>📝 <strong>Analyse des scripts</strong> — détecte les patterns PowerShell, VBS, BAT malveillants</p>
        <p>📦 <strong>Analyse PE</strong> — détecte les exécutables packés et obfusqués</p>
        <p>🔠 <strong>Double extension / RTL</strong> — détecte les techniques de camouflage de noms</p>
        <p>📡 <strong>Extensions ransomware</strong> — ${getSigCount(info)} extensions connues surveillées</p>
        <br>
        <p style="color:var(--text3);font-size:11px">Les signatures sont hébergées sur GitHub et mises à jour régulièrement. Cliquez sur "Mettre à jour" pour récupérer les dernières définitions.</p>
      </div>
    </div>
  `);
}

function getSigCount(info) {
  return info.source === 'cached' ? `${info.hashCount || 0}+ fichiers malveillants référencés` : 'base intégrée';
}

async function updateGPSigs() {
  const btn = document.getElementById('btn-update-sigs');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Téléchargement...'; }
  toast('Mise à jour des signatures GuardPilot en cours...', 'info');
  const res = await gp.updateGuardPilotSigs();
  if (res.success) {
    toast(`✅ Signatures mises à jour — v${res.version} (${res.hashCount} hachages)`, 'success');
    renderDefender();
  } else {
    toast(`Erreur : ${res.error || 'Connexion impossible'}`, 'error');
    if (btn) { btn.disabled = false; btn.textContent = '🔄 Mettre à jour les signatures'; }
  }
}

// ── Registry audit ────────────────────────────────────────────────────────────
async function renderRegistry() {
  setContent(`<div class="loading"><div class="spinner"></div>Analyse du registre...</div>`);
  const res = await gp.auditRegistry();
  const threats = res.threats || [];
  setContent(`
    <div class="topbar">
      <h1>📋 Audit Registre Windows</h1>
      <button class="btn btn-ghost" onclick="renderRegistry()">↺ Actualiser</button>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🚀 Entrées de démarrage automatique</div>
        <span class="badge ${threats.length>0?'badge-amber':'badge-green'}">${threats.length} suspect(s)</span>
      </div>
      ${threats.length === 0
        ? '<div style="padding:32px;text-align:center;color:var(--green);font-weight:700">✅ Aucune entrée suspecte dans le registre</div>'
        : `<div class="threat-list">${threats.map(t => renderThreatItem(t, true)).join('')}</div>`}
    </div>
    <div class="panel" style="margin-top:16px">
      <div class="panel-header"><div class="panel-title">ℹ️ Clés analysées</div></div>
      <div style="padding:14px 18px;font-family:var(--font-mono);font-size:11px;color:var(--text3);line-height:2">
        HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run<br>
        HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run<br>
        HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run<br>
        HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce<br>
        HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce
      </div>
    </div>
  `);
}

// ── Processes audit ────────────────────────────────────────────────────────────
async function renderProcesses() {
  setContent(`<div class="loading"><div class="spinner"></div>Analyse des processus...</div>`);
  const res = await gp.auditProcesses();
  const threats = res.threats || [];
  setContent(`
    <div class="topbar">
      <h1>⚙️ Audit Processus</h1>
      <button class="btn btn-ghost" onclick="renderProcesses()">↺ Actualiser</button>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🔍 Processus suspects détectés</div>
        <span class="badge ${threats.length>0?'badge-red':'badge-green'}">${threats.length}</span>
      </div>
      ${threats.length === 0
        ? '<div style="padding:32px;text-align:center;color:var(--green);font-weight:700">✅ Aucun processus suspect détecté</div>'
        : `<div class="threat-list">${threats.map(t => `
            <div class="threat-item ${severityClass(t.severity)}">
              <span class="threat-icon">${severityIcon(t.severity)}</span>
              <div class="threat-info">
                <div class="threat-desc">${severityBadge(t.severity)} ${escHtml(t.desc)}</div>
                <div class="threat-file">${escHtml(t.file||'')} ${t.pid?`(PID: ${t.pid})`:''}</div>
              </div>
              ${t.pid ? `<button class="btn btn-danger btn-sm" onclick="killPid(${t.pid})">⛔ Tuer</button>` : ''}
            </div>
          `).join('')}</div>`}
    </div>
  `);
}

async function killPid(pid) {
  if (!confirm(`Terminer le processus PID ${pid} ?`)) return;
  const res = await gp.killProcess(pid);
  if (res.success) { toast(`Processus ${pid} terminé`, 'success'); renderProcesses(); }
  else toast(res.error || 'Erreur', 'error');
}

// ── Network audit ─────────────────────────────────────────────────────────────
async function renderNetwork() {
  setContent(`<div class="loading"><div class="spinner"></div>Analyse réseau...</div>`);
  const res = await gp.auditNetwork();
  const threats = res.threats || [];
  setContent(`
    <div class="topbar">
      <h1>🌐 Audit Réseau</h1>
      <button class="btn btn-ghost" onclick="renderNetwork()">↺ Actualiser</button>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🔌 Connexions suspectes</div>
        <span class="badge ${threats.length>0?'badge-red':'badge-green'}">${threats.length}</span>
      </div>
      ${threats.length === 0
        ? '<div style="padding:32px;text-align:center;color:var(--green);font-weight:700">✅ Aucune connexion réseau suspecte</div>'
        : `<div class="threat-list">${threats.map(t => renderThreatItem(t, true)).join('')}</div>`}
    </div>
  `);
}

// ── Vulnerabilities ───────────────────────────────────────────────────────────
async function renderVulns() {
  setContent(`<div class="loading"><div class="spinner"></div>Vérification de sécurité...</div>`);
  const res = await gp.auditVulnerabilities();
  const checks = res.checks || [];
  const fails = checks.filter(c => c.status === 'FAIL').length;
  const warns = checks.filter(c => c.status === 'WARN').length;
  setContent(`
    <div class="topbar">
      <h1>🔐 Vérification de sécurité</h1>
      <button class="btn btn-ghost" onclick="renderVulns()">↺ Actualiser</button>
    </div>
    <div style="display:flex;gap:12px;margin-bottom:16px">
      <div class="panel" style="flex:1;margin-bottom:0">
        <div style="padding:14px 18px;text-align:center">
          <div style="font-size:28px;font-weight:900;color:${fails>0?'var(--red)':warns>0?'var(--amber)':'var(--green)'}">${checks.length - fails - warns}</div>
          <div style="font-size:11px;color:var(--text3)">Vérifications OK</div>
        </div>
      </div>
      <div class="panel" style="flex:1;margin-bottom:0">
        <div style="padding:14px 18px;text-align:center">
          <div style="font-size:28px;font-weight:900;color:var(--amber)">${warns}</div>
          <div style="font-size:11px;color:var(--text3)">Avertissements</div>
        </div>
      </div>
      <div class="panel" style="flex:1;margin-bottom:0">
        <div style="padding:14px 18px;text-align:center">
          <div style="font-size:28px;font-weight:900;color:var(--red)">${fails}</div>
          <div style="font-size:11px;color:var(--text3)">Problèmes critiques</div>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><div class="panel-title">🔐 Résultats de l'audit de sécurité</div></div>
      <div class="vuln-list">
        ${checks.map(c => `
          <div class="vuln-item">
            <div class="vuln-status vuln-${c.status==='OK'?'ok':c.status==='FAIL'?'fail':c.status==='WARN'?'warn':'unknown'}">
              ${c.status==='OK'?'✅':c.status==='FAIL'?'❌':c.status==='WARN'?'⚠️':'❔'}
            </div>
            <div style="flex:1">
              <div class="vuln-label">${escHtml(c.label)}</div>
              <div class="vuln-desc">${escHtml(c.desc)}</div>
            </div>
            ${severityBadge(c.severity)}
          </div>
        `).join('')}
      </div>
    </div>
  `);
}

// ── Quarantine ────────────────────────────────────────────────────────────────
async function renderQuarantine() {
  setContent(`<div class="loading"><div class="spinner"></div></div>`);
  const items = await gp.getQuarantine();
  setContent(`
    <div class="topbar">
      <h1>🔒 Quarantaine</h1>
      <button class="btn btn-ghost" onclick="renderQuarantine()">↺ Actualiser</button>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🔒 Fichiers en quarantaine</div>
        <span class="badge badge-blue">${items.length} fichier(s)</span>
      </div>
      ${items.length === 0
        ? '<div style="padding:32px;text-align:center;color:var(--text3)">Aucun fichier en quarantaine</div>'
        : `<table class="data-table">
            <thead><tr><th>Fichier original</th><th>Date</th><th>Actions</th></tr></thead>
            <tbody>
              ${items.map(item => `
                <tr>
                  <td style="font-family:var(--font-mono);font-size:11px">${escHtml(item.original)}</td>
                  <td>${fmtDate(item.date)}</td>
                  <td>
                    <div style="display:flex;gap:6px">
                      <button class="btn btn-ghost btn-sm" onclick="restoreQt('${escHtml(item.quarantined)}','${escHtml(item.original)}')">↩ Restaurer</button>
                      <button class="btn btn-danger btn-sm" onclick="deleteQt('${escHtml(item.quarantined)}')">🗑 Supprimer</button>
                    </div>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>`}
    </div>
  `);
}

async function restoreQt(qp, op) {
  if (!confirm('Restaurer ce fichier ? Il sera de nouveau accessible.')) return;
  const res = await gp.restoreQuarantine({ quarPath:qp, originalPath:op });
  if (res.success) { toast('Fichier restauré', 'success'); renderQuarantine(); }
  else toast(res.error || 'Erreur', 'error');
}
async function deleteQt(qp) {
  if (!confirm('Supprimer définitivement ce fichier ?')) return;
  const res = await gp.deleteQuarantine(qp);
  if (res.success) { toast('Fichier supprimé définitivement', 'success'); renderQuarantine(); }
  else toast(res.error || 'Erreur', 'error');
}

// ── History ───────────────────────────────────────────────────────────────────
async function renderHistory() {
  const history = await gp.getScanHistory();
  setContent(`
    <div class="topbar">
      <h1>📅 Historique des scans</h1>
      <button class="btn btn-ghost" onclick="if(confirm('Effacer tout l\\'historique ?')){gp.clearHistory().then(()=>renderHistory())}">🗑 Effacer</button>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">📊 Scans effectués</div>
        <span class="badge badge-blue">${history.length}</span>
      </div>
      ${history.length === 0
        ? '<div style="padding:32px;text-align:center;color:var(--text3)">Aucun scan dans l\'historique</div>'
        : `<table class="data-table">
            <thead><tr><th>Date</th><th>Type</th><th>Menaces</th><th>Statut</th></tr></thead>
            <tbody>
              ${history.map(h => `
                <tr>
                  <td>${fmtDate(h.date)}</td>
                  <td><span class="badge badge-blue">${h.type || 'rapide'}</span></td>
                  <td>${typeof h.threats === 'number' ? h.threats : (h.threats?.length || 0)}</td>
                  <td>${(typeof h.threats === 'number' ? h.threats : (h.threats?.length || 0)) > 0
                    ? '<span class="badge badge-red">Menaces trouvées</span>'
                    : '<span class="badge badge-green">Propre</span>'}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>`}
    </div>
  `);
}

// ── License ───────────────────────────────────────────────────────────────────
async function renderLicense() {
  const lic = State.license;
  if (!lic) return;
  if (lic.status === 'active' && lic.owner) {
    setContent(`
      <div class="topbar"><h1>🔑 Licence</h1></div>
      <div class="license-card">
        <div class="license-icon">👑</div>
        <div class="license-title" style="color:var(--blue)">Version propriétaire</div>
        <div class="license-sub">Accès permanent — SOS INFO LUDO<br>Toutes les fonctionnalités débloquées</div>
      </div>
    `); return;
  }
  if (lic.status === 'active') {
    setContent(`
      <div class="topbar"><h1>🔑 Licence</h1></div>
      <div class="license-card">
        <div class="license-icon">✅</div>
        <div class="license-title" style="color:var(--green)">Licence active</div>
        <div class="license-sub">Clé : <strong>${lic.key||''}</strong></div>
        <button class="btn btn-danger" style="margin-top:16px" onclick="deactivateLic()">Désactiver</button>
      </div>
    `); return;
  }
  const isExpired = lic.status === 'expired';
  setContent(`
    <div class="topbar"><h1>🔑 Licence</h1></div>
    <div class="license-card">
      <div class="license-icon">${isExpired?'⛔':'⏳'}</div>
      <div class="license-title" style="color:${isExpired?'var(--red)':'var(--amber)'}">
        ${isExpired ? 'Période d\'essai expirée' : `Essai — ${lic.remaining} jour(s) restant(s)`}
      </div>
      <div class="license-sub">Activez une licence pour un accès permanent à GuardPilot Pro.</div>
      <div style="margin-bottom:14px">
        <input class="form-input" id="lic-key" placeholder="GRDP-XXXXXXXX-XXXX" style="margin-bottom:10px"/>
        <button class="btn btn-primary" style="width:100%" onclick="activateLic()">🔑 Activer la licence</button>
      </div>
      <div style="font-size:11px;color:var(--text3)">Achetez une clé sur sosinfoludo.fr — 15€ à vie</div>
    </div>
  `);
}
async function activateLic() {
  const key = document.getElementById('lic-key')?.value?.trim();
  if (!key) return;
  const res = await gp.activateLicense(key);
  if (res.success) { toast('✅ Licence activée !', 'success'); State.license = await gp.checkLicense(); renderLicense(); }
  else toast(res.error || 'Clé invalide', 'error');
}
async function deactivateLic() {
  if (!confirm('Désactiver la licence ?')) return;
  await gp.deactivateLicense();
  State.license = await gp.checkLicense();
  renderLicense();
}

// ── Scheduled Tasks ───────────────────────────────────────────────────────────
async function renderTasks() {
  setContent(`<div class="loading"><div class="spinner"></div>Analyse des tâches planifiées...</div>`);
  const res = await gp.auditTasks();
  const threats = res.threats || [];
  setContent(`
    <div class="topbar">
      <h1>📆 Tâches planifiées</h1>
      <button class="btn btn-ghost" onclick="renderTasks()">↺ Actualiser</button>
    </div>
    <div class="panel">
      <div style="padding:12px 18px;font-size:12px;color:var(--text2)">
        Détection de tâches planifiées malveillantes: emplacements dangereux (Temp/Public), abus d'outils système (certutil, mshta, wscript, regsvr32...) avec téléchargement ou exécution de code encodé.
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🚨 Tâches suspectes détectées</div>
        <span class="badge ${threats.length>0?'badge-red':'badge-green'}">${threats.length}</span>
      </div>
      ${threats.length === 0
        ? '<div style="padding:32px;text-align:center;color:var(--green);font-weight:700">✅ Aucune tâche planifiée suspecte</div>'
        : `<div class="threat-list">${threats.map(t => `
            <div class="threat-item ${severityClass(t.severity)}">
              <span class="threat-icon">${severityIcon(t.severity)}</span>
              <div class="threat-info">
                <div class="threat-desc">${severityBadge(t.severity)} ${escHtml(t.desc)}</div>
                <div class="threat-file">${escHtml(t.file||'')} ${t.taskName?`<span style="color:var(--text3)"> — Tâche: ${escHtml(t.taskName)}</span>`:''}</div>
              </div>
              ${t.canFix && t.taskName ? `
                <button class="btn btn-danger btn-sm" onclick="removeTask('${escHtml(t.taskName.replace(/'/g,"&#39;"))}','${escHtml((t.taskPath||'\\\\').replace(/'/g,"&#39;"))}')">
                  🗑 Supprimer
                </button>` : ''}
            </div>
          `).join('')}</div>`}
    </div>
  `);
}

async function removeTask(name, taskPath) {
  if (!confirm(`Supprimer la tâche planifiée "${name}" ?`)) return;
  const res = await gp.removeScheduledTask({ taskName: name, taskPath });
  if (res.success) { toast('Tâche planifiée supprimée', 'success'); renderTasks(); }
  else toast(res.error || 'Erreur', 'error');
}

// ── Services ──────────────────────────────────────────────────────────────────
async function renderServices() {
  setContent(`<div class="loading"><div class="spinner"></div>Analyse des services Windows...</div>`);
  const res = await gp.auditServices();
  const threats = res.threats || [];
  setContent(`
    <div class="topbar">
      <h1>🔧 Services Windows</h1>
      <button class="btn btn-ghost" onclick="renderServices()">↺ Actualiser</button>
    </div>
    <div class="panel">
      <div style="padding:12px 18px;font-size:12px;color:var(--text2)">
        Détection de services installés depuis des emplacements suspects (Temp, Public, AppData\\Roaming).
        Les malwares s'installent souvent comme service Windows pour démarrer automatiquement.
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🔧 Services suspects</div>
        <span class="badge ${threats.length>0?'badge-red':'badge-green'}">${threats.length}</span>
      </div>
      ${threats.length === 0
        ? '<div style="padding:32px;text-align:center;color:var(--green);font-weight:700">✅ Aucun service suspect détecté</div>'
        : `<div class="threat-list">${threats.map(t => renderThreatItem(t, true)).join('')}</div>`}
    </div>
  `);
}

// ── Browser Extensions ────────────────────────────────────────────────────────
async function renderExtensions() {
  setContent(`<div class="loading"><div class="spinner"></div>Analyse des extensions navigateurs...</div>`);
  const res = await gp.auditExtensions();
  const threats = res.threats || [];
  setContent(`
    <div class="topbar">
      <h1>🧩 Extensions navigateurs</h1>
      <button class="btn btn-ghost" onclick="renderExtensions()">↺ Actualiser</button>
    </div>
    <div class="panel">
      <div style="padding:12px 18px;font-size:12px;color:var(--text2)">
        Analyse des extensions Chrome, Edge, Brave et Opera. Détection d'extensions avec permissions
        dangereuses: accès à toutes les URLs, blocage réseau, messagerie native, accès clipboard,
        proxy, debugger. Ces permissions permettent l'espionnage, le vol de mots de passe ou le détournement de trafic.
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🧩 Extensions suspectes</div>
        <span class="badge ${threats.length>0?'badge-amber':'badge-green'}">${threats.length}</span>
      </div>
      ${threats.length === 0
        ? '<div style="padding:32px;text-align:center;color:var(--green);font-weight:700">✅ Aucune extension suspecte détectée</div>'
        : `<div class="threat-list">${threats.map(t => `
            <div class="threat-item ${severityClass(t.severity)}">
              <span class="threat-icon">${severityIcon(t.severity)}</span>
              <div class="threat-info">
                <div class="threat-desc">${severityBadge(t.severity)} ${escHtml(t.desc)}</div>
                <div class="threat-file">${escHtml(t.file||'')}</div>
                ${t.extId ? `<div style="font-size:10px;color:var(--text3);margin-top:2px">ID: ${escHtml(t.extId)} — ${escHtml(t.browser||'')}</div>` : ''}
              </div>
              <div class="threat-actions">
                <a class="btn btn-ghost btn-sm" href="#" onclick="toast('Désactivez l\\'extension dans les paramètres de votre navigateur','info')">ℹ️ Info</a>
              </div>
            </div>
          `).join('')}</div>`}
    </div>
  `);
}

// ── Advanced Audit ────────────────────────────────────────────────────────────
async function renderAdvanced() {
  setContent(`<div class="loading"><div class="spinner"></div>Audit avancé en cours... (peut prendre 20-30 secondes)</div>`);
  const res = await gp.auditAdvanced();

  const sections = [
    { key:'wmi',     icon:'👻', title:'Persistance WMI (fileless)', desc:'Abonnements WMI utilisés pour exécuter du code sans fichier sur le disque' },
    { key:'hosts',   icon:'🌐', title:'Fichier HOSTS (DNS hijack)',  desc:'Détournement de noms de domaine vers des serveurs malveillants' },
    { key:'ifeo',    icon:'🎯', title:'IFEO — Détournement processus', desc:'Image File Execution Options: redirige l\'exécution de programmes légitimes' },
    { key:'appinit', icon:'💉', title:'AppInit_DLLs (injection DLL)', desc:'DLL injectée automatiquement dans tous les processus Windows' },
    { key:'shadows', icon:'💾', title:'Copies fantômes (Shadow Copies)', desc:'Absence = ransomware a effacé vos sauvegardes ou elles n\'ont jamais été activées' },
  ];

  const allThreats = [
    ...(res.wmi||[]), ...(res.hosts||[]), ...(res.ifeo||[]),
    ...(res.appinit||[]), ...(res.shadows||[]),
  ];

  let html = `
    <div class="topbar">
      <h1>🔬 Audit avancé</h1>
      <button class="btn btn-ghost" onclick="renderAdvanced()">↺ Actualiser</button>
    </div>
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px">
      ${sections.map(s => {
        const sThreats = (res[s.key]||[]);
        const hasThreats = sThreats.length > 0;
        return `
          <div class="panel" style="margin-bottom:0;border-left:3px solid ${hasThreats?'var(--red)':'var(--green)'}">
            <div style="padding:14px 16px">
              <div style="font-size:20px;margin-bottom:6px">${s.icon}</div>
              <div style="font-size:12px;font-weight:700;color:var(--text);margin-bottom:4px">${s.title}</div>
              <div style="font-size:10px;color:var(--text3);margin-bottom:8px">${s.desc}</div>
              <span class="badge ${hasThreats?'badge-red':'badge-green'}">${hasThreats?sThreats.length+' alerte(s)':'✅ OK'}</span>
            </div>
          </div>
        `;
      }).join('')}
    </div>
  `;

  if (allThreats.length === 0) {
    html += `<div class="panel"><div style="padding:32px;text-align:center;color:var(--green);font-weight:700">✅ Aucune menace avancée détectée</div></div>`;
  } else {
    html += `
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">🚨 Menaces avancées détectées</div>
          <span class="badge badge-red">${allThreats.length}</span>
        </div>
        <div class="threat-list">
          ${allThreats.map(t => `
            <div class="threat-item ${severityClass(t.severity)}">
              <span class="threat-icon">${severityIcon(t.severity)}</span>
              <div class="threat-info">
                <div class="threat-desc">${severityBadge(t.severity)} ${escHtml(t.desc)}</div>
                <div class="threat-file">${escHtml(t.file||'')}</div>
                ${t.recommendation ? `<div style="font-size:10px;color:var(--blue);margin-top:4px">💡 ${escHtml(t.recommendation)}</div>` : ''}
              </div>
              ${t.canFix && t.fixType === 'wmi' ? `
                <button class="btn btn-danger btn-sm" onclick="removeWMI('${escHtml(t.wmiClass||'')}','${escHtml(t.wmiName||'')}')">🗑 Supprimer</button>
              ` : ''}
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  // Also show tasks/services threats in the same view
  const tasksThreats = res.tasks || [];
  const svcThreats   = res.services || [];
  if (tasksThreats.length > 0 || svcThreats.length > 0) {
    html += `
      <div class="panel">
        <div class="panel-header"><div class="panel-title">⚙️ Tâches & Services suspects</div></div>
        <div class="threat-list">
          ${[...tasksThreats, ...svcThreats].map(t => renderThreatItem(t, true)).join('')}
        </div>
      </div>
    `;
  }

  setContent(html);
}

async function removeWMI(cls, name) {
  if (!confirm(`Supprimer l'abonnement WMI "${name}" ?`)) return;
  const res = await gp.removeWMISubscription({ wmiClass: cls, wmiName: name });
  if (res.success) { toast('Abonnement WMI supprimé', 'success'); renderAdvanced(); }
  else toast(res.error || 'Erreur', 'error');
}

// ── Boot ─────────────────────────────────────────────────────────────────────
async function boot() {
  await new Promise(r => setTimeout(r, 1200));
  const lic = await gp.checkLicense();
  State.license = lic;

  if (lic.status === 'expired') {
    renderShell();
    navTo('license');
    return;
  }

  // Setup realtime listeners
  gp.onRealtimeThreat((threat) => {
    State.rtThreats.push(threat);
    State.rtFeed.push({ ...threat, threat: true });
    toast(`🚨 Menace détectée: ${threat.desc?.slice(0,60)||''}`, 'error');
    const feed = document.getElementById('rt-feed-container');
    if (feed && State.page === 'realtime') {
      const entry = document.createElement('div');
      entry.className = 'rt-entry threat';
      entry.innerHTML = `<span>🚨</span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(threat.desc||'')}</span><span style="font-size:10px;color:var(--text3)">${new Date().toLocaleTimeString('fr-FR')}</span>`;
      feed.insertBefore(entry, feed.firstChild);
    }
    const sbBadge = document.querySelector('.sb-item[onclick*="quarantine"] .badge-count');
    if (sbBadge) sbBadge.textContent = State.rtThreats.length;
  });

  gp.onRealtimeActivity((activity) => {
    State.rtFeed.push({ ...activity, threat: false });
    if (State.rtFeed.length > 500) State.rtFeed.shift();
    const feed = document.getElementById('rt-feed-container');
    if (feed && State.page === 'realtime') {
      const entry = document.createElement('div');
      entry.className = 'rt-entry activity';
      entry.innerHTML = `<span>📄</span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(activity.path||'')}</span><span style="font-size:10px;color:var(--text3)">${new Date().toLocaleTimeString('fr-FR')}</span>`;
      feed.insertBefore(entry, feed.firstChild);
      while (feed.children.length > 50) feed.removeChild(feed.lastChild);
    }
  });

  const rtStatus = await gp.getRealtimeStatus();
  State.realtimeActive = rtStatus.active;

  // Load preferences
  const prefs = await gp.getPrefs();
  applyTheme(prefs.theme || 'dark');

  // Load exclusions into state
  State.exclusions = await gp.getExclusions();

  renderShell();
  navTo('dashboard');
  initDragDrop();
}

document.addEventListener('DOMContentLoaded', boot);
