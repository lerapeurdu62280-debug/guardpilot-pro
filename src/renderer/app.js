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
      <div style="font-size:10px;color:var(--text3)">SOS INFO LUDO</div>
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
  { id:'defender',     icon:'🪟', label:'Windows Defender',      section:'PROTECTION' },
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
    case 'license':    renderLicense(); break;
    default: renderDashboard();
  }
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function renderDashboard() {
  setContent(`<div class="loading"><div class="spinner"></div>Analyse de sécurité...</div>`);
  const [stats, lastScan, defRes, rtStatus] = await Promise.all([
    gp.getStats(), gp.getLastScan(), gp.getDefenderStatus(), gp.getRealtimeStatus()
  ]);
  State.stats = stats;
  State.defenderStatus = defRes.status;
  State.realtimeActive = rtStatus.active;
  updateRtStatus();

  const ds = defRes.status || {};
  const rtOk = rtStatus.active;
  const avOk = ds.AntivirusEnabled;
  const fwOk = true; // assumed
  const lastThreatCount = lastScan?.count || 0;

  // Score calculation
  let score = 100;
  if (!rtOk) score -= 25;
  if (!avOk) score -= 30;
  if (lastThreatCount > 0) score -= Math.min(30, lastThreatCount * 5);
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
        <button class="btn btn-ghost" onclick="gp.exportPDF()">📄 Rapport PDF</button>
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
        <div class="status-card" style="--card-color:${avOk?'#10B981':'#EF4444'}">
          <div class="sc-icon">🪟</div>
          <div class="sc-label">Windows Defender</div>
          <div class="sc-value" style="color:${avOk?'var(--green)':'var(--red)'};font-size:16px">${avOk?'Actif':'Inactif'}</div>
          <div class="sc-sub">Antivirus Microsoft</div>
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
          <button class="btn btn-ghost btn-sm" onclick="gp.exportPDF()">📄 PDF</button>
        </div>
      </div>
      <div class="threat-list">
        ${threats.map(t => renderThreatItem(t, true)).join('')}
      </div>
    </div>
  `;
  toast(`⚠️ ${threats.length} menace(s) détectée(s) !`, 'error');
}

function renderThreatItem(t, withActions = false) {
  return `
    <div class="threat-item ${severityClass(t.severity)}">
      <span class="threat-icon">${severityIcon(t.severity)}</span>
      <div class="threat-info">
        <div class="threat-desc">${severityBadge(t.severity)} ${escHtml(t.desc)}</div>
        <div class="threat-file">${escHtml(t.file||'')}</div>
        ${t.date ? `<div style="font-size:10px;color:var(--text3);margin-top:2px">${fmtDate(t.date)}</div>` : ''}
      </div>
      ${withActions && t.file ? `
        <div class="threat-actions">
          <button class="btn btn-danger btn-sm" onclick="quarantineOne('${escHtml(t.file.replace(/'/g,"&#39;"))}')">🔒 Quarantaine</button>
          ${t.canFix ? `<button class="btn btn-ghost btn-sm" onclick="fixThreat(${JSON.stringify(JSON.stringify(t)).slice(1,-1)})">🔧 Corriger</button>` : ''}
        </div>
      ` : ''}
    </div>
  `;
}

async function quarantineOne(filePath) {
  const res = await gp.quarantineFile(filePath);
  if (res.success) { toast('Fichier mis en quarantaine', 'success'); }
  else toast(res.error || 'Erreur', 'error');
}

async function quarantineAll() {
  let count = 0;
  for (const t of State.currentThreats) {
    if (t.file) {
      const res = await gp.quarantineFile(t.file);
      if (res.success) count++;
    }
  }
  toast(`${count} fichier(s) mis en quarantaine`, 'success');
}

async function fixThreat(t) {
  if (t.type === 'SUSPICIOUS_AUTORUN' && t.fixKey && t.fixName) {
    const res = await gp.removeAutorun({ key: t.fixKey, name: t.fixName });
    if (res.success) toast('Entrée de démarrage supprimée', 'success');
    else toast(res.error || 'Erreur', 'error');
  }
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

// ── Windows Defender ──────────────────────────────────────────────────────────
async function renderDefender() {
  setContent(`<div class="loading"><div class="spinner"></div>Chargement Windows Defender...</div>`);
  const [defRes, threatRes] = await Promise.all([gp.getDefenderStatus(), gp.getDefenderThreats()]);
  const ds = defRes.status || {};
  const threats = threatRes.threats || [];

  const rows = [
    { label:'Antivirus', val:ds.AntivirusEnabled, ok:ds.AntivirusEnabled },
    { label:'Anti-spyware', val:ds.AntispywareEnabled, ok:ds.AntispywareEnabled },
    { label:'Protection temps réel', val:ds.RealTimeProtectionEnabled, ok:ds.RealTimeProtectionEnabled },
    { label:'Protection accès', val:ds.OnAccessProtectionEnabled, ok:ds.OnAccessProtectionEnabled },
    { label:'Protection réseau (NIS)', val:ds.NISEnabled, ok:ds.NISEnabled },
    { label:'Protection IOAV', val:ds.IoavProtectionEnabled, ok:ds.IoavProtectionEnabled },
    { label:'Signatures antivirus MAJ', val:ds.AntivirusSignatureLastUpdated ? fmtDate(ds.AntivirusSignatureLastUpdated) : '—', ok:!!ds.AntivirusSignatureLastUpdated },
    { label:'Signatures anti-spyware MAJ', val:ds.AntispywareSignatureLastUpdated ? fmtDate(ds.AntispywareSignatureLastUpdated) : '—', ok:true },
  ];

  setContent(`
    <div class="topbar">
      <h1>🪟 Windows Defender</h1>
      <div class="topbar-actions">
        <button class="btn btn-primary" onclick="updateDefSigs()">🔄 Mettre à jour signatures</button>
        <button class="btn btn-ghost" onclick="renderDefender()">↺ Actualiser</button>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><div class="panel-title">🔒 Statut Windows Defender</div></div>
      <table class="data-table">
        <thead><tr><th>Composant</th><th>Statut</th></tr></thead>
        <tbody>
          ${rows.map(r => `
            <tr>
              <td><strong>${escHtml(r.label)}</strong></td>
              <td>
                ${r.val === true ? `<span class="badge badge-green">✅ Actif</span>`
                  : r.val === false ? `<span class="badge badge-red">❌ Inactif</span>`
                  : `<span style="font-size:12px">${escHtml(String(r.val))}</span>`}
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🦠 Menaces détectées par Defender</div>
        <span class="badge ${threats.length>0?'badge-red':'badge-green'}">${threats.length}</span>
      </div>
      ${threats.length === 0
        ? '<div style="padding:32px;text-align:center;color:var(--green);font-weight:700">✅ Aucune menace active dans Windows Defender</div>'
        : `<div class="threat-list">${threats.map(t => renderThreatItem(t)).join('')}</div>`}
    </div>
  `);
}

async function updateDefSigs() {
  toast('Mise à jour des signatures en cours...', 'info');
  const res = await gp.updateDefenderSigs();
  if (res.success) { toast('Signatures mises à jour !', 'success'); renderDefender(); }
  else toast('Impossible de mettre à jour (connexion requise)', 'warn');
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

  renderShell();
  navTo('dashboard');
}

document.addEventListener('DOMContentLoaded', boot);
