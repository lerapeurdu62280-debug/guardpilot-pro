'use strict';

const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs   = require('fs');
const os   = require('os');

let Store;
try { Store = require('electron-store'); } catch(e) { Store = null; }
const store = Store ? new Store({ encryptionKey: 'GRDP2026SOSINFOLUDO' }) : { get:(k,d)=>d, set:()=>{}, delete:()=>{} };

let BUILD_VARIANT = 'client';
try { BUILD_VARIANT = require('../../package.json').buildVariant || 'client'; } catch(e) {}

// Lazy-load modules to avoid startup delay
let scanner = null;
let realtime = null;
let advanced = null;
function getScanner()  { if (!scanner)  scanner  = require('./scanner');        return scanner; }
function getRealtime() { if (!realtime) realtime = require('./realtime');       return realtime; }
function getAdvanced() { if (!advanced) advanced = require('./audit_advanced'); return advanced; }

// ── License ───────────────────────────────────────────────────────────────────
const LICENSE_SECRET = 'SOSINFOLUDO2026GP';
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
ipcMain.handle('quick-scan', async () => {
  let progress = [];
  const threats = await getScanner().quickScan((p) => {
    progress.push(p);
    mainWindow?.webContents.send('scan-progress', p);
  });
  const scan = { id: Date.now(), type:'quick', date:new Date().toISOString(), threats, count:threats.length };
  const history = store.get('scanHistory', []);
  history.unshift({ ...scan, threats: threats.length });
  store.set('scanHistory', history.slice(0, 50));
  store.set('lastScan', scan);
  return { success:true, ...scan };
});

ipcMain.handle('full-scan', async () => {
  const threats = await getScanner().fullScan((p) => mainWindow?.webContents.send('scan-progress', p));
  const scan = { id:Date.now(), type:'full', date:new Date().toISOString(), threats, count:threats.length };
  const history = store.get('scanHistory', []);
  history.unshift({ ...scan, threats: threats.length });
  store.set('scanHistory', history.slice(0, 50));
  store.set('lastScan', scan);
  return { success:true, ...scan };
});

ipcMain.handle('custom-scan', async (_, folderPath) => {
  const threats = await getScanner().customScan(folderPath,
    (p) => mainWindow?.webContents.send('scan-progress', p));
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
  return { success:true, checks: getScanner().auditVulnerabilities() };
});
ipcMain.handle('get-defender-status', async () => {
  return { success:true, status: getScanner().getDefenderStatus() };
});
ipcMain.handle('update-defender-signatures', async () => {
  return { success: getScanner().updateDefenderSignatures() };
});
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

// ── Real-time protection IPC ───────────────────────────────────────────────────
ipcMain.handle('start-realtime', () => {
  getRealtime().startRealtime(
    (threat) => mainWindow?.webContents.send('realtime-threat', threat),
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
ipcMain.handle('get-stats', () => ({
  totalScans: store.get('scanHistory', []).length,
  threatsFound: store.get('scanHistory', []).reduce((s,h) => s+(typeof h.threats==='number'?h.threats:0), 0),
  quarantined: store.get('quarantine', []).length,
  lastScan: store.get('scanHistory', [])[0]?.date || null,
}));
ipcMain.handle('clear-history', () => { store.set('scanHistory', []); return true; });

// ── PDF Export ────────────────────────────────────────────────────────────────
ipcMain.handle('export-pdf', async () => {
  const savePath = await dialog.showSaveDialog(mainWindow, {
    title: 'Exporter le rapport de sécurité',
    defaultPath: `GuardPilot_Rapport_${new Date().toISOString().slice(0,10)}.pdf`,
    filters: [{ name:'PDF', extensions:['pdf'] }]
  });
  if (savePath.canceled || !savePath.filePath) return { success:false };
  try {
    const data = await mainWindow.webContents.printToPDF({ printBackground:true, pageSize:'A4' });
    fs.writeFileSync(savePath.filePath, data);
    shell.openPath(savePath.filePath);
    return { success:true };
  } catch(e) { return { success:false, error:e.message }; }
});

ipcMain.on('win-min',   () => mainWindow?.minimize());
ipcMain.on('win-max',   () => mainWindow?.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize());
ipcMain.on('win-close', () => mainWindow?.close());

// ── Main window ────────────────────────────────────────────────────────────────
let mainWindow;
app.whenReady().then(() => {
  mainWindow = new BrowserWindow({
    width:1340, height:860, minWidth:1100, minHeight:680,
    frame:false, backgroundColor:'#0A0F1E',
    webPreferences: { preload:path.join(__dirname,'preload.js'), contextIsolation:true, nodeIntegration:false },
    icon: path.join(__dirname,'../../assets/icon.ico'),
    show:false,
  });
  mainWindow.loadFile(path.join(__dirname,'../renderer/index.html'));
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    // Auto-start real-time if enabled
    if (store.get('realtimeEnabled', true)) {
      try {
        getRealtime().startRealtime(
          (threat) => mainWindow?.webContents.send('realtime-threat', threat),
          (activity) => mainWindow?.webContents.send('realtime-activity', activity)
        );
      } catch(e) {}
    }
  });
  mainWindow.on('closed', () => { try { getRealtime().stopRealtime(); } catch(e) {} });
});
app.on('window-all-closed', () => app.quit());
