'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { execSync } = require('child_process');
const { WHITELIST_PATHS } = require('./threats');

function isWhitelisted(p) {
  const lower = (p || '').toLowerCase();
  return WHITELIST_PATHS.some(w => lower.includes(w.toLowerCase()));
}

// ── Scheduled Tasks Audit ─────────────────────────────────────────────────────
function auditScheduledTasks() {
  const threats = [];
  try {
    const out = execSync(
      `powershell -NonInteractive -Command "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | ForEach-Object { $t=$_; $t.Actions | ForEach-Object { [PSCustomObject]@{TaskName=$t.TaskName;TaskPath=$t.TaskPath;Execute=$_.Execute;Arguments=$_.Arguments} } } | ConvertTo-Json"`,
      { encoding: 'utf8', timeout: 20000 }
    );
    if (!out.trim()) return threats;
    let tasks = JSON.parse(out);
    if (!Array.isArray(tasks)) tasks = [tasks];

    const suspiciousLocs = ['\\temp\\', '\\tmp\\', '\\public\\', '\\appdata\\roaming\\', '\\programdata\\', '\\users\\default\\'];
    const lolbas = ['certutil.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe', 'regsvr32.exe', 'rundll32.exe', 'bitsadmin.exe', 'odbcconf.exe', 'installutil.exe'];
    const dangerousArgs = ['http://', 'https://', 'download', '-enc', 'bypass', 'hidden', 'base64', 'frombase64', '-w 1', '-windowstyle'];

    for (const task of tasks) {
      if (!task || !task.Execute) continue;
      const exec = (task.Execute || '').toLowerCase();
      const args = (task.Arguments || '').toLowerCase();

      if (isWhitelisted(exec)) continue;

      const inSuspLoc = suspiciousLocs.some(s => exec.includes(s));
      if (inSuspLoc) {
        threats.push({
          type: 'SUSPICIOUS_SCHEDULED_TASK',
          severity: 'CRITICAL',
          desc: `Tâche planifiée dans emplacement dangereux: "${task.TaskName}" → ${task.Execute}`,
          file: task.Execute,
          taskName: task.TaskName,
          taskPath: task.TaskPath,
          canFix: true, fixType: 'scheduled-task',
        });
        continue;
      }

      const usesLolbas = lolbas.some(l => exec.endsWith(l) || exec.includes('\\' + l));
      const hasSuspArgs = dangerousArgs.some(a => args.includes(a));
      if (usesLolbas && hasSuspArgs) {
        threats.push({
          type: 'LOLBAS_SCHEDULED_TASK',
          severity: 'HIGH',
          desc: `Tâche avec outil système et arguments suspects: "${task.TaskName}" — ${path.basename(exec)} ${args.slice(0, 100)}`,
          file: task.Execute,
          taskName: task.TaskName,
          canFix: true, fixType: 'scheduled-task',
        });
      }
    }
  } catch(e) {}
  return threats;
}

// ── Services Audit ────────────────────────────────────────────────────────────
function auditServices() {
  const threats = [];
  try {
    const out = execSync(
      `powershell -NonInteractive -Command "Get-WmiObject Win32_Service | Select-Object Name,DisplayName,PathName,StartMode,State | ConvertTo-Json"`,
      { encoding: 'utf8', timeout: 15000 }
    );
    if (!out.trim()) return threats;
    let services = JSON.parse(out);
    if (!Array.isArray(services)) services = [services];

    const suspiciousLocs = ['\\temp\\', '\\tmp\\', '\\public\\', '\\appdata\\roaming\\', '\\users\\public\\'];
    const safePaths = ['\\windows\\', '\\program files\\', '\\program files (x86)\\'];

    for (const svc of services) {
      if (!svc || !svc.PathName) continue;
      const rawPath = svc.PathName.replace(/"/g, '').toLowerCase().split(' ')[0].trim();

      if (isWhitelisted(rawPath)) continue;
      if (safePaths.some(sp => rawPath.includes(sp))) continue;

      const inSuspLoc = suspiciousLocs.some(s => rawPath.includes(s));
      if (inSuspLoc) {
        threats.push({
          type: 'SUSPICIOUS_SERVICE',
          severity: 'CRITICAL',
          desc: `Service Windows depuis emplacement dangereux: "${svc.DisplayName || svc.Name}" → ${svc.PathName}`,
          file: svc.PathName,
          serviceName: svc.Name,
        });
      }
    }
  } catch(e) {}
  return threats;
}

// ── WMI Subscriptions Audit (fileless persistence) ────────────────────────────
function auditWMISubscriptions() {
  const threats = [];

  // ActiveScript consumers (VBS/JS executed by WMI)
  try {
    const out = execSync(
      `powershell -NonInteractive -Command "Get-WMIObject -Namespace root\\\\subscription -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue | Select-Object Name,ScriptText | ConvertTo-Json"`,
      { encoding: 'utf8', timeout: 8000 }
    );
    if (out.trim()) {
      let items = JSON.parse(out);
      if (!Array.isArray(items)) items = [items];
      for (const item of items) {
        if (!item || !item.Name) continue;
        threats.push({
          type: 'WMI_SUBSCRIPTION',
          severity: 'CRITICAL',
          desc: `Persistance WMI ActiveScript: "${item.Name}" — ${(item.ScriptText || '').slice(0, 100)}`,
          file: `WMI\\root\\subscription\\ActiveScript\\${item.Name}`,
          canFix: true, fixType: 'wmi',
          wmiClass: 'ActiveScriptEventConsumer', wmiName: item.Name,
        });
      }
    }
  } catch(e) {}

  // CommandLine consumers (shell commands executed by WMI)
  try {
    const out = execSync(
      `powershell -NonInteractive -Command "Get-WMIObject -Namespace root\\\\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | Select-Object Name,CommandLineTemplate | ConvertTo-Json"`,
      { encoding: 'utf8', timeout: 8000 }
    );
    if (out.trim()) {
      let items = JSON.parse(out);
      if (!Array.isArray(items)) items = [items];
      for (const item of items) {
        if (!item || !item.Name) continue;
        threats.push({
          type: 'WMI_SUBSCRIPTION',
          severity: 'CRITICAL',
          desc: `Persistance WMI CommandLine: "${item.Name}" → ${(item.CommandLineTemplate || '').slice(0, 100)}`,
          file: `WMI\\root\\subscription\\CommandLine\\${item.Name}`,
          canFix: true, fixType: 'wmi',
          wmiClass: 'CommandLineEventConsumer', wmiName: item.Name,
        });
      }
    }
  } catch(e) {}

  // Event filters (non-standard)
  try {
    const out = execSync(
      `powershell -NonInteractive -Command "Get-WMIObject -Namespace root\\\\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Select-Object Name,Query | ConvertTo-Json"`,
      { encoding: 'utf8', timeout: 8000 }
    );
    if (out.trim()) {
      let items = JSON.parse(out);
      if (!Array.isArray(items)) items = [items];
      const defaultFilters = ['scm event log filter', 'bvtfilter', 'nteventslogfilter'];
      for (const item of items) {
        if (!item || !item.Name) continue;
        if (defaultFilters.some(f => (item.Name || '').toLowerCase().includes(f))) continue;
        threats.push({
          type: 'WMI_FILTER',
          severity: 'HIGH',
          desc: `Filtre WMI non standard: "${item.Name}" — ${(item.Query || '').slice(0, 100)}`,
          file: `WMI\\root\\subscription\\__EventFilter\\${item.Name}`,
        });
      }
    }
  } catch(e) {}

  return threats;
}

// ── Hosts File Audit ──────────────────────────────────────────────────────────
function auditHostsFile() {
  const threats = [];
  const hostsPath = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
  try {
    const content = fs.readFileSync(hostsPath, 'utf8');
    const sensitiveHosts = [
      'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook',
      'instagram', 'twitter', 'netflix', 'bankofamerica', 'citibank', 'chase',
      'wellsfargo', 'ing', 'bnpparibas', 'lcl', 'creditagricole', 'societegenerale',
      'windowsupdate', 'update.microsoft', 'defender', 'kaspersky', 'avast',
      'bitdefender', 'norton', 'malwarebytes', 'symantec',
    ];

    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length < 2) continue;
      const ip = parts[0];
      const hostnames = parts.slice(1).filter(h => !h.startsWith('#'));

      for (const hostname of hostnames) {
        const h = hostname.toLowerCase();
        if (h === 'localhost') continue;
        const isSensitive = sensitiveHosts.some(s => h.includes(s));

        if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '0.0.0.0' && isSensitive) {
          threats.push({
            type: 'HOSTS_HIJACK',
            severity: 'CRITICAL',
            desc: `Fichier HOSTS — redirection phishing: ${hostname} → ${ip}`,
            file: hostsPath,
          });
        } else if ((ip === '0.0.0.0' || ip === '127.0.0.1') && isSensitive &&
                   (h.includes('update') || h.includes('defender') || h.includes('kaspersky') || h.includes('avast') || h.includes('bitdefender') || h.includes('norton') || h.includes('malwarebytes'))) {
          threats.push({
            type: 'HOSTS_AV_BLOCK',
            severity: 'HIGH',
            desc: `Fichier HOSTS — site antivirus/MAJ bloqué: ${hostname} (malware bloquant les mises à jour ?)`,
            file: hostsPath,
          });
        } else if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '0.0.0.0' && h !== 'localhost') {
          threats.push({
            type: 'HOSTS_CUSTOM_ENTRY',
            severity: 'MEDIUM',
            desc: `Entrée personnalisée dans HOSTS: ${hostname} → ${ip}`,
            file: hostsPath,
          });
        }
      }
    }
  } catch(e) {}
  return threats;
}

// ── IFEO Audit (Image File Execution Options — process hijacking) ─────────────
function auditIFEO() {
  const threats = [];
  try {
    const out = execSync(
      `powershell -NonInteractive -Command "Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options' | ForEach-Object { $d=Get-ItemProperty $_.PSPath -EA SilentlyContinue; if($d.Debugger){[PSCustomObject]@{Process=$_.PSChildName;Debugger=$d.Debugger}} } | ConvertTo-Json"`,
      { encoding: 'utf8', timeout: 8000 }
    );
    if (!out.trim()) return threats;
    let items = JSON.parse(out);
    if (!Array.isArray(items)) items = [items];
    const legitDebuggers = ['vsjitdebugger.exe', 'drwtsn32.exe', 'ntsd.exe', 'windbg.exe', 'cdb.exe'];
    for (const item of items) {
      if (!item || !item.Debugger) continue;
      const dbg = item.Debugger.toLowerCase();
      if (legitDebuggers.some(d => dbg.includes(d))) continue;
      threats.push({
        type: 'IFEO_HIJACK',
        severity: 'CRITICAL',
        desc: `Détournement IFEO: "${item.Process}" → "${item.Debugger}" (exécution détournée)`,
        file: `HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\${item.Process}`,
      });
    }
  } catch(e) {}
  return threats;
}

// ── AppInit_DLLs Audit (DLL injection into all processes) ─────────────────────
function auditAppInitDLLs() {
  const threats = [];
  const keys = [
    'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows',
    'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows',
  ];
  for (const key of keys) {
    try {
      const out = execSync(
        `powershell -NonInteractive -Command "Get-ItemPropertyValue '${key}' -Name AppInit_DLLs -EA SilentlyContinue"`,
        { encoding: 'utf8', timeout: 5000 }
      ).trim();
      if (out && out !== '' && out !== '0') {
        threats.push({
          type: 'APPINIT_DLLS',
          severity: 'CRITICAL',
          desc: `AppInit_DLLs configuré — injection automatique dans tous les processus: "${out}"`,
          file: key,
        });
      }
    } catch(e) {}
  }
  return threats;
}

// ── Browser Extensions Audit ──────────────────────────────────────────────────
function auditBrowserExtensions() {
  const threats = [];
  const home = os.homedir();
  const browsers = [
    { name: 'Chrome', base: path.join(home, 'AppData', 'Local', 'Google', 'Chrome', 'User Data') },
    { name: 'Edge',   base: path.join(home, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data') },
    { name: 'Brave',  base: path.join(home, 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data') },
    { name: 'Opera',  base: path.join(home, 'AppData', 'Roaming', 'Opera Software', 'Opera Stable') },
  ];
  const highRiskPerms = ['<all_urls>', 'webRequestBlocking', 'nativeMessaging', 'clipboardRead', 'debugger', 'proxy'];
  const medRiskPerms  = ['webRequest', 'cookies', 'history', 'tabs', 'bookmarks', 'downloads', 'management', 'clipboardWrite'];

  for (const browser of browsers) {
    if (!fs.existsSync(browser.base)) continue;
    let profiles = ['Default'];
    try {
      profiles = fs.readdirSync(browser.base).filter(d => d === 'Default' || /^Profile \d+$/.test(d));
    } catch(e) {}

    for (const profile of profiles) {
      const extDir = path.join(browser.base, profile, 'Extensions');
      if (!fs.existsSync(extDir)) continue;
      let extIds;
      try { extIds = fs.readdirSync(extDir).filter(d => d !== 'Temp'); } catch(e) { continue; }

      for (const extId of extIds) {
        let manifest = null, manifestPath = '';
        try {
          const extPath = path.join(extDir, extId);
          const versions = fs.readdirSync(extPath).sort().reverse();
          for (const v of versions) {
            const mp = path.join(extPath, v, 'manifest.json');
            if (fs.existsSync(mp)) {
              manifest = JSON.parse(fs.readFileSync(mp, 'utf8'));
              manifestPath = mp;
              break;
            }
          }
        } catch(e) { continue; }
        if (!manifest) continue;

        const allPerms = [
          ...(manifest.permissions || []),
          ...(manifest.host_permissions || []),
          ...(manifest.optional_permissions || []),
        ].map(p => String(p));

        const high = highRiskPerms.filter(p => allPerms.includes(p));
        const med  = medRiskPerms.filter(p => allPerms.includes(p));

        if (high.length >= 2 || (high.includes('<all_urls>') && med.length >= 2)) {
          threats.push({
            type: 'SUSPICIOUS_EXTENSION',
            severity: 'HIGH',
            desc: `Extension ${browser.name} permissions dangereuses: "${manifest.name || extId}" — ${high.join(', ')}`,
            file: manifestPath,
            extId, browser: browser.name, extName: manifest.name || extId,
          });
        } else if (high.length === 1 && med.length >= 3) {
          threats.push({
            type: 'SUSPICIOUS_EXTENSION',
            severity: 'MEDIUM',
            desc: `Extension ${browser.name} permissions étendues: "${manifest.name || extId}" — ${[...high, ...med.slice(0,3)].join(', ')}`,
            file: manifestPath,
            extId, browser: browser.name, extName: manifest.name || extId,
          });
        }
      }
    }
  }
  return threats;
}

// ── Shadow Copies Audit ───────────────────────────────────────────────────────
function auditShadowCopies() {
  const threats = [];
  try {
    const out = execSync(
      `powershell -NonInteractive -Command "(Get-WmiObject Win32_ShadowCopy | Measure-Object).Count"`,
      { encoding: 'utf8', timeout: 8000 }
    ).trim();
    const count = parseInt(out) || 0;
    if (count === 0) {
      threats.push({
        type: 'NO_SHADOW_COPIES',
        severity: 'MEDIUM',
        desc: 'Aucune copie fantôme — récupération impossible en cas de ransomware. Activez la Protection du Système.',
        file: 'Système',
        recommendation: 'Panneau de configuration → Système → Protection du système → Configurer',
      });
    }
  } catch(e) {}
  return threats;
}

// ── PE Sections Analysis ──────────────────────────────────────────────────────
const MALICIOUS_PE_SECTIONS = [
  '.upx0', '.upx1', '.upx2',
  '.vmp0', '.vmp1',
  '.themida',
  '.enigma1', '.enigma2',
  '.mpress1', '.mpress2',
  '.petite', '.aspack',
  '.nsp0', '.nsp1',
  '.packed', '.shrink1',
  '.yoda', '.execryptor',
];

function analyzePESections(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    if (buf.length < 0x40) return null;
    const peOffset = buf.readUInt32LE(0x3C);
    if (peOffset + 24 > buf.length) return null;
    if (buf.toString('ascii', peOffset, peOffset + 4) !== 'PE\0\0') return null;
    const numSections = buf.readUInt16LE(peOffset + 6);
    if (numSections === 0 || numSections > 96) return null;
    const optHeaderSize = buf.readUInt16LE(peOffset + 20);
    const sectionsOffset = peOffset + 24 + optHeaderSize;
    const sections = [];
    for (let i = 0; i < numSections; i++) {
      const secOff = sectionsOffset + i * 40;
      if (secOff + 8 > buf.length) break;
      const name = buf.slice(secOff, secOff + 8).toString('ascii').replace(/\0/g, '').toLowerCase();
      sections.push(name);
    }
    const found = sections.filter(s => MALICIOUS_PE_SECTIONS.includes(s));
    return found.length > 0 ? found : null;
  } catch(e) { return null; }
}

// ── Double Extension / Name Tricks ────────────────────────────────────────────
function checkDoubleExtension(filePath) {
  const basename = path.basename(filePath);
  const lower = basename.toLowerCase();
  const dangerous = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr', '.pif', '.com', '.hta', '.js', '.cmd'];
  const fake = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.jpg', '.jpeg', '.png', '.mp4', '.mp3', '.zip', '.txt', '.rar', '.iso'];

  // RTL override trick
  if (basename.includes('\u202E')) return { detected: true, name: basename, trick: 'RTL Unicode override' };

  for (const f of fake) {
    for (const d of dangerous) {
      if (lower.endsWith(f + d)) return { detected: true, name: basename, trick: 'double extension' };
    }
  }
  return { detected: false };
}

// ── Digital Signature Verification ────────────────────────────────────────────
function checkSignature(filePath) {
  try {
    const escaped = filePath.replace(/'/g, "''");
    const out = execSync(
      `powershell -NonInteractive -Command "(Get-AuthenticodeSignature '${escaped}').Status"`,
      { encoding: 'utf8', timeout: 5000 }
    ).trim();
    return out;
  } catch(e) { return 'Unknown'; }
}

// ── Combined Advanced Audit ───────────────────────────────────────────────────
function runAdvancedAudit() {
  return {
    tasks:    auditScheduledTasks(),
    services: auditServices(),
    wmi:      auditWMISubscriptions(),
    hosts:    auditHostsFile(),
    ifeo:     auditIFEO(),
    appinit:  auditAppInitDLLs(),
    shadows:  auditShadowCopies(),
  };
}

module.exports = {
  auditScheduledTasks,
  auditServices,
  auditWMISubscriptions,
  auditHostsFile,
  auditIFEO,
  auditAppInitDLLs,
  auditBrowserExtensions,
  auditShadowCopies,
  analyzePESections,
  checkDoubleExtension,
  checkSignature,
  runAdvancedAudit,
};
