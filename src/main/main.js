'use strict';

const { app, BrowserWindow, ipcMain, dialog, shell, Tray, Menu, nativeImage } = require('electron');
const { Worker } = require('worker_threads');
const path = require('path');
const fs   = require('fs');
const os   = require('os');

let Store;
try { Store = require('electron-store'); } catch(e) { Store = null; }

// ── Load .env (secrets stay out of git) ──────────────────────────────────────
try {
  fs.readFileSync(path.join(__dirname, '../../.env'), 'utf8').split('\n').forEach(line => {
    const m = line.match(/^([^#=\s][^=]*)=(.*)$/);
    if (m) process.env[m[1].trim()] = m[2].trim();
  });
} catch(e) {}

const store = Store ? new Store({ encryptionKey: process.env.STORE_KEY || 'GRDP2026SOSINFOLUDO' }) : { get:(k,d)=>d, set:()=>{}, delete:()=>{} };

let BUILD_VARIANT = process.env.BUILD_VARIANT || 'client';
try { BUILD_VARIANT = require('../../package.json').buildVariant || BUILD_VARIANT; } catch(e) {}

const { updateSignatures, getSignaturesInfo } = require('./updater');

// Lazy-load modules to avoid startup delay
let scanner = null;
let realtime = null;
let advanced = null;
function getScanner()  { if (!scanner)  scanner  = require('./scanner');        return scanner; }
function getRealtime() { if (!realtime) realtime = require('./realtime');       return realtime; }
function getAdvanced() { if (!advanced) advanced = require('./audit_advanced'); return advanced; }

// ── License ───────────────────────────────────────────────────────────────────
const LICENSE_SECRET = process.env.LICENSE_SECRET || '';
function isValidKey(raw) {
  const k = (raw||'').trim().toUpperCase();
  if (!/^GRDP-[A-Z0-9]{8}-[A-Z0-9]{4}$/.test(k)) return false;
  const seg = k.split('-')[1];
  const body = seg.slice(0,6), chk = seg.slice(6,8);
  let sum = 0;
  for(let i=0;i<body.length;i++) sum+=body.charCodeAt(i);
  for(let i=0;i<LICENSE_SECRET.length;i++) sum+=LICENSE_SECRET.charCodeAt(i);
  return chk === (sum%(36*36)).toString(36).toUpperCase().padStart(2,'0');
}
ipcMain.handle('check-license', () => {
  if (BUILD_VARIANT==='owner') return { status:'active', remaining:9999, owner:true };
  const key = store.get('licenseKey','');
  const trialStart = store.get('trialStart',null);
  const now = Date.now();
  if (!trialStart) store.set('trialStart',now);
  const remaining = Math.max(0, 30-Math.floor((now-(trialStart||now))/86400000));
  if (key && isValidKey(key)) return { status:'active', key, remaining:9999 };
  if (remaining>0) return { status:'trial', remaining };
  return { status:'expired', remaining:0 };
});
ipcMain.handle('activate-license', (_,key) => {
  if (BUILD_VARIANT==='owner') return { success:true };
  if (isValidKey(key)) { store.set('licenseKey',(key||'').trim().toUpperCase()); return { success:true }; }
  return { success:false, error:'Clé invalide. Format : GRDP-XXXXXXXX-XXXX' };
});
ipcMain.handle('deactivate-license', () => { store.delete('licenseKey'); return true; });

// ── Quarantine dir ────────────────────────────────────────────────────────────
const QUARANTINE_DIR = path.join(os.homedir(), 'AppData', 'Local', 'GuardPilot', 'Quarantine');

// ── Scan IPC ──────────────────────────────────────────────────────────────────
// ── Worker-based scan (keeps main thread free → UI stays fluid) ───────────────
function runScanWorker(scanType, folderPath = null) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(path.join(__dirname, 'scanner-worker.js'), {
      workerData: { scanType, folderPath }
    });
    let lastSend = 0;
    worker.on('message', (msg) => {
      if (msg.type === 'progress') {
        const now = Date.now();
        if (now - lastSend >= 120) {
          lastSend = now;
          mainWindow?.webContents.send('scan-progress', msg.data);
        }
      } else if (msg.type === 'done') {
        resolve(msg.threats || []);
      } else if (msg.type === 'error') {
        reject(new Error(msg.message));
      }
    });
    worker.on('error', reject);
    worker.on('exit', (code) => {
      if (code !== 0) reject(new Error(`Scanner worker exited with code ${code}`));
    });
  });
}

ipcMain.handle('quick-scan', async () => {
  const threats = await runScanWorker('quick');
  const scan = { id: Date.now(), type:'quick', date:new Date().toISOString(), threats, count:threats.length };
  const history = store.get('scanHistory', []);
  history.unshift({ ...scan, threats: threats.length });
  store.set('scanHistory', history.slice(0, 50));
  store.set('lastScan', scan);
  return { success:true, ...scan };
});

ipcMain.handle('full-scan', async () => {
  const threats = await runScanWorker('full');
  const scan = { id:Date.now(), type:'full', date:new Date().toISOString(), threats, count:threats.length };
  const history = store.get('scanHistory', []);
  history.unshift({ ...scan, threats: threats.length });
  store.set('scanHistory', history.slice(0, 50));
  store.set('lastScan', scan);
  return { success:true, ...scan };
});

ipcMain.handle('custom-scan', async (_, folderPath) => {
  const threats = await runScanWorker('custom', folderPath);
  return { success:true, threats, count:threats.length, date:new Date().toISOString() };
});

ipcMain.handle('choose-scan-folder', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Choisir un dossier à analyser',
    properties: ['openDirectory'],
  });
  return result.canceled ? null : result.filePaths[0];
});

// ── Audit IPC ─────────────────────────────────────────────────────────────────
ipcMain.handle('audit-registry', async () => {
  return { success:true, threats: getScanner().auditRegistry() };
});
ipcMain.handle('audit-processes', async () => {
  return { success:true, threats: getScanner().auditProcesses() };
});
ipcMain.handle('audit-network', async () => {
  return { success:true, threats: getScanner().auditNetwork() };
});
ipcMain.handle('audit-vulnerabilities', async () => {
  return { success:true, checks: await getScanner().auditVulnerabilities() };
});
ipcMain.handle('get-defender-status', async () => {
  return { success:true, status: getScanner().getDefenderStatus() };
});
ipcMain.handle('update-defender-signatures', async () => {
  return { success: getScanner().updateDefenderSignatures() };
});
ipcMain.handle('update-guardpilot-signatures', async () => {
  try {
    const sigs = await updateSignatures();
    getScanner().reloadSignatures();
    return { success: true, version: sigs.version, updated: sigs.updated, hashCount: (sigs.known_hashes||[]).length };
  } catch(e) {
    return { success: false, error: e.message };
  }
});
ipcMain.handle('get-signatures-info', () => getSignaturesInfo());
ipcMain.handle('get-defender-threats', async () => {
  return { success:true, threats: getScanner().getWindowsDefenderThreats() };
});

// ── Quarantine IPC ─────────────────────────────────────────────────────────────
ipcMain.handle('quarantine-file', async (_, filePath) => {
  const res = getScanner().quarantineFile(filePath, QUARANTINE_DIR);
  if (res.success) {
    const q = store.get('quarantine', []);
    q.push({ original: filePath, quarantined: res.dest, date: new Date().toISOString() });
    store.set('quarantine', q);
  }
  return res;
});
ipcMain.handle('get-quarantine', () => store.get('quarantine', []));
ipcMain.handle('restore-quarantine', (_, { quarPath, originalPath }) => {
  const res = getScanner().restoreQuarantined(quarPath, originalPath);
  if (res.success) {
    const q = store.get('quarantine', []).filter(f => f.quarantined !== quarPath);
    store.set('quarantine', q);
  }
  return res;
});
ipcMain.handle('delete-quarantine', (_, quarPath) => {
  const res = getScanner().deleteQuarantined(quarPath);
  if (res.success) {
    const q = store.get('quarantine', []).filter(f => f.quarantined !== quarPath);
    store.set('quarantine', q);
  }
  return res;
});

// ── Advanced Audit IPC ────────────────────────────────────────────────────────
ipcMain.handle('audit-tasks',      async () => ({ success:true, threats: getAdvanced().auditScheduledTasks() }));
ipcMain.handle('audit-services',   async () => ({ success:true, threats: getAdvanced().auditServices() }));
ipcMain.handle('audit-wmi',        async () => ({ success:true, threats: getAdvanced().auditWMISubscriptions() }));
ipcMain.handle('audit-hosts',      async () => ({ success:true, threats: getAdvanced().auditHostsFile() }));
ipcMain.handle('audit-ifeo',       async () => ({ success:true, threats: getAdvanced().auditIFEO() }));
ipcMain.handle('audit-appinit',    async () => ({ success:true, threats: getAdvanced().auditAppInitDLLs() }));
ipcMain.handle('audit-extensions', async () => ({ success:true, threats: getAdvanced().auditBrowserExtensions() }));
ipcMain.handle('audit-shadows',    async () => ({ success:true, threats: getAdvanced().auditShadowCopies() }));
ipcMain.handle('audit-advanced',   async () => {
  const adv = getAdvanced();
  return { success:true, ...adv.runAdvancedAudit() };
});

// Delete public malware folder
ipcMain.handle('delete-public-malware', async (_, folderPath) => {
  try {
    require('child_process').execSync(`powershell -NonInteractive -Command "Remove-Item '${folderPath.replace(/'/g,"''")}' -Recurse -Force"`, { timeout: 10000 });
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
});

// Remove scheduled task
ipcMain.handle('remove-scheduled-task', async (_, { taskName, taskPath }) => {
  try {
    const tn = (taskName || '').replace(/'/g, "''");
    const tp = (taskPath || '\\').replace(/'/g, "''");
    require('child_process').execSync(`powershell -NonInteractive -Command "Unregister-ScheduledTask -TaskName '${tn}' -TaskPath '${tp}' -Confirm:\\$false"`, { timeout: 10000 });
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
});

// Remove WMI subscription
ipcMain.handle('remove-wmi-subscription', async (_, { wmiClass, wmiName }) => {
  try {
    const cn = (wmiClass || '').replace(/'/g, "''");
    const nn = (wmiName || '').replace(/'/g, "''");
    require('child_process').execSync(`powershell -NonInteractive -Command "Get-WMIObject -Namespace root\\\\subscription -Class ${cn} | Where-Object {$_.Name -eq '${nn}'} | Remove-WmiObject"`, { timeout: 10000 });
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
});

// ── Fix IPC ───────────────────────────────────────────────────────────────────
ipcMain.handle('remove-autorun', (_, { key, name }) => {
  return getScanner().removeAutorun(key, name);
});
ipcMain.handle('kill-process', (_, pid) => {
  try {
    require('child_process').execSync(`taskkill /F /PID ${pid}`, { timeout: 5000 });
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
});

// ── Delete file directly ──────────────────────────────────────────────────────
ipcMain.handle('delete-file', async (_, filePath) => {
  try { fs.unlinkSync(filePath); return { success: true }; }
  catch(e) { return { success: false, error: e.message }; }
});

// ── Action log ────────────────────────────────────────────────────────────────
ipcMain.handle('log-action', (_, action) => {
  const log = store.get('actionLog', []);
  log.unshift({ ...action, date: new Date().toISOString() });
  store.set('actionLog', log.slice(0, 500));
  return true;
});
ipcMain.handle('get-action-log', () => store.get('actionLog', []));
ipcMain.handle('clear-action-log', () => { store.set('actionLog', []); return true; });

// ── Exclusions ────────────────────────────────────────────────────────────────
ipcMain.handle('get-exclusions', () => store.get('exclusions', []));
ipcMain.handle('add-exclusion', (_, p) => {
  const excl = store.get('exclusions', []);
  if (!excl.includes(p)) { excl.push(p); store.set('exclusions', excl); }
  return store.get('exclusions', []);
});
ipcMain.handle('remove-exclusion', (_, p) => {
  const excl = store.get('exclusions', []).filter(e => e !== p);
  store.set('exclusions', excl);
  return excl;
});
ipcMain.handle('choose-exclusion-path', async () => {
  const res = await dialog.showOpenDialog(mainWindow, {
    title: 'Choisir un dossier ou fichier à exclure',
    properties: ['openDirectory', 'openFile'],
  });
  return res.canceled ? null : res.filePaths[0];
});

// ── Preferences (theme, etc.) ─────────────────────────────────────────────────
ipcMain.handle('get-prefs', () => store.get('prefs', { theme: 'dark' }));
ipcMain.handle('set-pref', (_, { key, value }) => {
  const prefs = store.get('prefs', { theme: 'dark' });
  prefs[key] = value;
  store.set('prefs', prefs);
  return prefs;
});

// ── Scheduled scans (Windows Task Scheduler) ──────────────────────────────────
ipcMain.handle('get-scheduled-scans', async () => {
  try {
    const out = require('child_process').execSync(
      `powershell -NonInteractive -Command "Get-ScheduledTask -TaskPath '\\GuardPilot\\' -ErrorAction SilentlyContinue | Select-Object TaskName,State,Description | ConvertTo-Json"`,
      { encoding: 'utf8', timeout: 8000 }
    ).trim();
    if (!out) return [];
    const tasks = JSON.parse(out);
    return Array.isArray(tasks) ? tasks : [tasks];
  } catch(e) { return []; }
});
ipcMain.handle('schedule-scan', async (_, { scanType, trigger }) => {
  try {
    const appExe = process.execPath.replace(/'/g, "''");
    const taskName = `GuardPilot_${scanType}`;
    const desc = `Scan ${scanType} automatique — GuardPilot Pro`;
    // trigger: { type: 'daily'|'weekly', time: '08:00', day: 'Monday' }
    let triggerPS = '';
    if (trigger.type === 'daily') {
      triggerPS = `New-ScheduledTaskTrigger -Daily -At '${trigger.time}'`;
    } else {
      triggerPS = `New-ScheduledTaskTrigger -Weekly -DaysOfWeek ${trigger.day} -At '${trigger.time}'`;
    }
    const ps = `
      $action = New-ScheduledTaskAction -Execute '${appExe}' -Argument '--scan-${scanType}';
      $trigger = ${triggerPS};
      $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable;
      Register-ScheduledTask -TaskName '${taskName}' -TaskPath '\\GuardPilot\\' -Action $action -Trigger $trigger -Settings $settings -Description '${desc}' -Force
    `.replace(/\n\s+/g, ' ');
    require('child_process').execSync(`powershell -NonInteractive -Command "${ps.replace(/"/g, '\\"')}"`, { timeout: 10000 });
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
});
ipcMain.handle('unschedule-scan', async (_, taskName) => {
  try {
    require('child_process').execSync(
      `powershell -NonInteractive -Command "Unregister-ScheduledTask -TaskName '${taskName}' -TaskPath '\\\\GuardPilot\\\\' -Confirm:\\$false -ErrorAction SilentlyContinue"`,
      { timeout: 8000 }
    );
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
});

// ── Analyze single file ───────────────────────────────────────────────────────
ipcMain.handle('analyze-file', async (_, filePath) => {
  try {
    const threats = getScanner().analyzeFile(filePath);
    return { success: true, threats, file: filePath };
  } catch(e) { return { success: false, error: e.message }; }
});

// ── Export Word (.doc HTML) ───────────────────────────────────────────────────
ipcMain.handle('export-word', async (_, data) => {
  const savePath = await dialog.showSaveDialog(mainWindow, {
    title: 'Exporter le rapport Word',
    defaultPath: `GuardPilot_Rapport_${new Date().toISOString().slice(0,10)}.doc`,
    filters: [{ name:'Word Document', extensions:['doc'] }],
  });
  if (savePath.canceled || !savePath.filePath) return { success: false };
  try {
    const html = buildReportHTML(data || {});
    const wordHtml = `<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40"><head><meta charset="UTF-8"></head><body>${html}</body></html>`;
    fs.writeFileSync(savePath.filePath, wordHtml, 'utf8');
    shell.openPath(savePath.filePath);
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
});

// ── Open RepairPilot with prefilled data ──────────────────────────────────────
ipcMain.handle('open-repairpilot', async (_, data) => {
  try {
    const rpDir = path.join(os.homedir(), 'RepairPilot');
    const tmpFile = path.join(os.tmpdir(), 'guardpilot_to_repairpilot.json');
    fs.writeFileSync(tmpFile, JSON.stringify(data), 'utf8');
    require('child_process').spawn('npm', ['start'], {
      cwd: rpDir, detached: true, stdio: 'ignore',
      env: { ...process.env, GP_IMPORT: tmpFile }
    }).unref();
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
});

// ── Real-time protection IPC ───────────────────────────────────────────────────
ipcMain.handle('start-realtime', () => {
  const { Notification } = require('electron');
  getRealtime().startRealtime(
    (threat) => {
      mainWindow?.webContents.send('realtime-threat', threat);
      // Windows native notification
      if (Notification.isSupported()) {
        new Notification({
          title: '🚨 GuardPilot — Menace détectée',
          body: (threat.desc || 'Fichier suspect détecté').slice(0, 120),
          urgency: 'critical',
        }).show();
      }
    },
    (activity) => mainWindow?.webContents.send('realtime-activity', activity)
  );
  store.set('realtimeEnabled', true);
  return { success: true };
});
ipcMain.handle('stop-realtime', () => {
  getRealtime().stopRealtime();
  store.set('realtimeEnabled', false);
  return { success: true };
});
ipcMain.handle('get-realtime-status', () => ({
  active: getRealtime().isActive(),
  enabled: store.get('realtimeEnabled', true),
}));

// ── History & stats IPC ───────────────────────────────────────────────────────
ipcMain.handle('get-scan-history', () => store.get('scanHistory', []));
ipcMain.handle('get-last-scan', () => store.get('lastScan', null));
ipcMain.handle('get-stats', () => {
  const history = store.get('scanHistory', []);
  const actionLog = store.get('actionLog', []);
  const now = new Date();
  const thisMonth = history.filter(h => {
    const d = new Date(h.date);
    return d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear();
  });
  return {
    totalScans: history.length,
    scansThisMonth: thisMonth.length,
    threatsFound: history.reduce((s,h) => s+(typeof h.threats==='number'?h.threats:0), 0),
    threatsThisMonth: thisMonth.reduce((s,h) => s+(typeof h.threats==='number'?h.threats:0), 0),
    quarantined: store.get('quarantine', []).length,
    actionsTotal: actionLog.length,
    lastScan: history[0]?.date || null,
    history,
  };
});
ipcMain.handle('clear-history', () => { store.set('scanHistory', []); return true; });

// ── PDF Export ────────────────────────────────────────────────────────────────
function buildReportHTML(data) {
  const now = new Date().toLocaleString('fr-FR');
  const threats = data.threats || [];
  const stats = data.stats || {};

  function severityLabel(s) {
    switch ((s||'').toUpperCase()) {
      case 'CRITICAL': return { label: 'CRITIQUE', color: '#EF4444', bg: '#FEE2E2' };
      case 'HIGH':     return { label: 'ÉLEVÉ',    color: '#F59E0B', bg: '#FEF3C7' };
      case 'MEDIUM':   return { label: 'MOYEN',    color: '#3B82F6', bg: '#DBEAFE' };
      default:         return { label: 'INFO',     color: '#6B7280', bg: '#F3F4F6' };
    }
  }

  const critical = threats.filter(t => (t.severity||'').toUpperCase() === 'CRITICAL').length;
  const high     = threats.filter(t => (t.severity||'').toUpperCase() === 'HIGH').length;
  const medium   = threats.filter(t => (t.severity||'').toUpperCase() === 'MEDIUM').length;

  const rows = threats.map((t, i) => {
    const sv = severityLabel(t.severity);
    return `
      <tr style="background:${i%2===0?'#fff':'#F9FAFB'}">
        <td style="padding:8px 12px;font-size:12px;color:#6B7280;white-space:nowrap">${i+1}</td>
        <td style="padding:8px 12px">
          <span style="background:${sv.bg};color:${sv.color};font-weight:700;font-size:11px;padding:2px 8px;border-radius:4px">${sv.label}</span>
        </td>
        <td style="padding:8px 12px;font-size:12px;font-weight:600;color:#1F2937">${escapeHtml(t.type||'')}</td>
        <td style="padding:8px 12px;font-size:12px;color:#374151">${escapeHtml(t.desc||'')}</td>
        <td style="padding:8px 12px;font-size:11px;color:#6B7280;word-break:break-all;max-width:250px">${escapeHtml(t.file||'—')}</td>
      </tr>`;
  }).join('');

  function escapeHtml(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background:#fff; color:#1F2937; }
  .header { background: linear-gradient(135deg,#0A0F1E 0%,#1E3A5F 100%); color:#fff; padding:32px 40px; }
  .header-top { display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; }
  .logo { font-size:24px; font-weight:800; letter-spacing:1px; }
  .logo span { color:#2563EB; }
  .subtitle { font-size:12px; color:#94A3B8; margin-top:4px; }
  .date { font-size:12px; color:#94A3B8; text-align:right; }
  .summary { display:flex; gap:20px; padding:24px 40px; background:#F8FAFC; border-bottom:1px solid #E5E7EB; }
  .stat-box { flex:1; background:#fff; border:1px solid #E5E7EB; border-radius:8px; padding:16px; text-align:center; }
  .stat-num { font-size:28px; font-weight:800; }
  .stat-lbl { font-size:11px; color:#6B7280; margin-top:4px; text-transform:uppercase; letter-spacing:0.5px; }
  .section { padding:24px 40px; }
  .section-title { font-size:16px; font-weight:700; color:#1F2937; margin-bottom:16px; padding-bottom:8px; border-bottom:2px solid #2563EB; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  thead tr { background:#1E3A5F; color:#fff; }
  thead th { padding:10px 12px; text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; font-weight:600; }
  tbody tr:hover { background:#EFF6FF; }
  .no-threats { text-align:center; padding:48px; color:#10B981; font-size:16px; font-weight:700; }
  .footer { text-align:center; padding:20px; font-size:11px; color:#9CA3AF; border-top:1px solid #E5E7EB; margin-top:20px; }
</style>
</head>
<body>
  <div class="header">
    <div class="header-top">
      <div>
        <div class="logo">🛡️ Guard<span>Pilot</span> Pro</div>
        <div class="subtitle">Rapport de sécurité — S.O.S INFO LUDO</div>
      </div>
      <div class="date">
        <div style="font-size:14px;font-weight:700">${now}</div>
        <div style="font-size:11px;color:#94A3B8;margin-top:2px">Date du rapport</div>
      </div>
    </div>
  </div>

  <div class="summary">
    <div class="stat-box">
      <div class="stat-num" style="color:#EF4444">${critical}</div>
      <div class="stat-lbl">Critiques</div>
    </div>
    <div class="stat-box">
      <div class="stat-num" style="color:#F59E0B">${high}</div>
      <div class="stat-lbl">Élevés</div>
    </div>
    <div class="stat-box">
      <div class="stat-num" style="color:#3B82F6">${medium}</div>
      <div class="stat-lbl">Moyens</div>
    </div>
    <div class="stat-box">
      <div class="stat-num" style="color:#1F2937">${threats.length}</div>
      <div class="stat-lbl">Total menaces</div>
    </div>
    <div class="stat-box">
      <div class="stat-num" style="color:#6B7280">${stats.totalScans||0}</div>
      <div class="stat-lbl">Scans effectués</div>
    </div>
    <div class="stat-box">
      <div class="stat-num" style="color:#8B5CF6">${stats.quarantined||0}</div>
      <div class="stat-lbl">Fichiers en quarantaine</div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Détail des menaces détectées</div>
    ${threats.length === 0
      ? `<div class="no-threats">✅ Aucune menace détectée — système sain</div>`
      : `<table>
          <thead><tr>
            <th>#</th><th>Sévérité</th><th>Type</th><th>Description</th><th>Fichier / Chemin</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>`
    }
  </div>

  <div class="footer">
    GuardPilot Pro v1.1.0 — S.O.S INFO LUDO — Rapport généré le ${now}
  </div>
</body>
</html>`;
}

ipcMain.handle('export-pdf', async (_, data) => {
  const savePath = await dialog.showSaveDialog(mainWindow, {
    title: 'Exporter le rapport de sécurité',
    defaultPath: `GuardPilot_Rapport_${new Date().toISOString().slice(0,10)}.pdf`,
    filters: [{ name:'PDF', extensions:['pdf'] }]
  });
  if (savePath.canceled || !savePath.filePath) return { success:false };
  try {
    const html = buildReportHTML(data || {});
    // Write HTML to temp file and load it in a hidden window
    const tmpHtml = path.join(os.tmpdir(), `guardpilot_report_${Date.now()}.html`);
    fs.writeFileSync(tmpHtml, html, 'utf8');

    const win = new BrowserWindow({
      show: false,
      width: 1200, height: 900,
      webPreferences: { nodeIntegration: false, contextIsolation: true }
    });
    await win.loadFile(tmpHtml);
    // Wait for page to fully render
    await new Promise(r => setTimeout(r, 800));
    const pdfData = await win.webContents.printToPDF({
      printBackground: true,
      pageSize: 'A4',
      margins: { marginType: 'custom', top: 0, bottom: 0, left: 0, right: 0 }
    });
    win.close();
    try { fs.unlinkSync(tmpHtml); } catch(e) {}
    fs.writeFileSync(savePath.filePath, pdfData);
    shell.openPath(savePath.filePath);
    return { success:true };
  } catch(e) { return { success:false, error:e.message }; }
});

ipcMain.on('win-min',   () => mainWindow?.minimize());
ipcMain.on('win-max',   () => mainWindow?.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize());
ipcMain.on('win-close', () => mainWindow?.close());

// Disable "Not Responding" hang detection — scan worker does heavy I/O
app.commandLine.appendSwitch('disable-hang-monitor');

// ── Systray ───────────────────────────────────────────────────────────────────
let tray = null;
const ICON_PATH = path.join(__dirname, '../../assets/icon.ico');

function buildTrayMenu() {
  const rtActive = (() => { try { return getRealtime().isActive?.() ?? store.get('realtimeEnabled', true); } catch(e) { return false; } })();
  return Menu.buildFromTemplate([
    { label: '🛡️  GuardPilot Pro', enabled: false },
    { type: 'separator' },
    { label: '🖥️  Ouvrir GuardPilot', click: () => { mainWindow?.show(); mainWindow?.focus(); } },
    { type: 'separator' },
    { label: rtActive ? '✅  Protection temps réel : Active' : '❌  Protection temps réel : Inactive', enabled: false },
    { label: rtActive ? 'Désactiver la protection' : 'Activer la protection', click: () => {
      try {
        if (rtActive) {
          getRealtime().stopRealtime();
          store.set('realtimeEnabled', false);
        } else {
          getRealtime().startRealtime(
            (threat) => mainWindow?.webContents.send('realtime-threat', threat),
            (activity) => mainWindow?.webContents.send('realtime-activity', activity)
          );
          store.set('realtimeEnabled', true);
        }
      } catch(e) {}
      if (tray) tray.setContextMenu(buildTrayMenu());
    }},
    { type: 'separator' },
    { label: '⚡  Scan rapide', click: () => { mainWindow?.show(); mainWindow?.webContents.send('tray-action', 'quick-scan'); } },
    { type: 'separator' },
    { label: '❌  Quitter', click: () => { app.isQuitting = true; app.quit(); } },
  ]);
}

function createTray() {
  tray = new Tray(ICON_PATH);
  tray.setToolTip('GuardPilot Pro — Protection active');
  tray.setContextMenu(buildTrayMenu());
  tray.on('click', () => { mainWindow?.show(); mainWindow?.focus(); });
  tray.on('double-click', () => { mainWindow?.show(); mainWindow?.focus(); });
}

// ── Auto-start IPC ─────────────────────────────────────────────────────────────
ipcMain.handle('get-autostart', () => app.getLoginItemSettings().openAtLogin);
ipcMain.handle('set-autostart', (_, enable) => {
  app.setLoginItemSettings({ openAtLogin: enable, openAsHidden: true, name: 'GuardPilot Pro' });
  store.set('autostart', enable);
  return true;
});

// ── Windows Defender IPC ───────────────────────────────────────────────────────
const { promisify } = require('util');
const execAsyncSys = promisify(require('child_process').exec);

ipcMain.handle('disable-defender', async () => {
  try {
    await execAsyncSys(
      `powershell -NonInteractive -Command "Set-MpPreference -DisableRealtimeMonitoring $true"`,
      { timeout: 10000 }
    );
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
});

ipcMain.handle('enable-defender', async () => {
  try {
    await execAsyncSys(
      `powershell -NonInteractive -Command "Set-MpPreference -DisableRealtimeMonitoring $false"`,
      { timeout: 10000 }
    );
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
});

ipcMain.handle('get-defender-realtime', async () => {
  try {
    const { stdout } = await execAsyncSys(
      `powershell -NonInteractive -Command "(Get-MpPreference).DisableRealtimeMonitoring"`,
      { encoding: 'utf8', timeout: 8000 }
    );
    return { disabled: stdout.trim() === 'True' };
  } catch(e) { return { disabled: false }; }
});

// ── Main window ────────────────────────────────────────────────────────────────
let mainWindow;
app.whenReady().then(() => {
  mainWindow = new BrowserWindow({
    width:1340, height:860, minWidth:1100, minHeight:680,
    frame:false, backgroundColor:'#0A0F1E',
    webPreferences: { preload:path.join(__dirname,'preload.js'), contextIsolation:true, nodeIntegration:false },
    icon: ICON_PATH,
    show:false,
  });
  mainWindow.loadFile(path.join(__dirname,'../renderer/index.html'));
  mainWindow.once('ready-to-show', () => {
    // Apply autostart setting on first launch
    if (store.get('autostart', false)) {
      app.setLoginItemSettings({ openAtLogin: true, openAsHidden: true, name: 'GuardPilot Pro' });
    }
    mainWindow.show();
    createTray();
    // Auto-start real-time if enabled
    if (store.get('realtimeEnabled', true)) {
      try {
        getRealtime().startRealtime(
          (threat) => { mainWindow?.webContents.send('realtime-threat', threat); if (tray) tray.setContextMenu(buildTrayMenu()); },
          (activity) => mainWindow?.webContents.send('realtime-activity', activity)
        );
      } catch(e) {}
    }
  });
  // Hide to tray instead of closing
  mainWindow.on('close', (e) => {
    if (!app.isQuitting) {
      e.preventDefault();
      mainWindow.hide();
      tray?.displayBalloon?.({ title: 'GuardPilot Pro', content: 'GuardPilot continue de protéger votre PC en arrière-plan.', iconType: 'info' });
    }
  });
  mainWindow.on('closed', () => { try { getRealtime().stopRealtime(); } catch(e) {} });
});
app.on('window-all-closed', () => { if (app.isQuitting) app.quit(); });
app.on('before-quit', () => { app.isQuitting = true; });
