'use strict';

const fs      = require('fs');
const path    = require('path');
const os      = require('os');
const crypto  = require('crypto');
const { execSync, exec } = require('child_process');
const { KNOWN_HASHES, SUSPICIOUS_STRINGS, SUSPICIOUS_PATHS,
        DANGEROUS_EXTENSIONS_IN_TEMP, RANSOMWARE_EXTENSIONS,
        SUSPICIOUS_PROCESS_PATTERNS, SUSPICIOUS_IP_RANGES, SAFE_PATHS } = require('./threats');

// ── Utilities ─────────────────────────────────────────────────────────────────
function sha256(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(buf).digest('hex');
  } catch(e) { return null; }
}

function fileEntropy(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    if (buf.length === 0) return 0;
    const freq = new Array(256).fill(0);
    for (const byte of buf) freq[byte]++;
    let entropy = 0;
    for (const f of freq) {
      if (f === 0) continue;
      const p = f / buf.length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  } catch(e) { return 0; }
}

function isPE(filePath) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(2);
    fs.readSync(fd, buf, 0, 2, 0);
    fs.closeSync(fd);
    return buf[0] === 0x4D && buf[1] === 0x5A; // MZ header
  } catch(e) { return false; }
}

function readStrings(filePath, minLen = 6) {
  try {
    const buf = fs.readFileSync(filePath);
    const strings = [];
    let current = '';
    for (const byte of buf) {
      if (byte >= 0x20 && byte < 0x7F) {
        current += String.fromCharCode(byte);
      } else {
        if (current.length >= minLen) strings.push(current);
        current = '';
      }
    }
    return strings.join(' ');
  } catch(e) { return ''; }
}

function ps(cmd, timeout = 10000) {
  try {
    return execSync(`powershell -NonInteractive -Command "${cmd.replace(/"/g, '\\"')}"`,
      { encoding: 'utf8', timeout }).trim();
  } catch(e) { return ''; }
}

function psJSON(cmd, timeout = 10000) {
  try {
    const out = execSync(`powershell -NonInteractive -Command "${cmd.replace(/"/g, '\\"')}"`,
      { encoding: 'utf8', timeout }).trim();
    if (!out) return null;
    const parsed = JSON.parse(out);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch(e) { return null; }
}

// ── Scan a single file ────────────────────────────────────────────────────────
function analyzeFile(filePath) {
  const threats = [];
  const ext = path.extname(filePath).toLowerCase();
  let stat;
  try { stat = fs.statSync(filePath); } catch(e) { return []; }
  if (stat.size > 50 * 1024 * 1024) return []; // Skip > 50MB
  if (stat.size === 0) return [];

  // 1. Hash check
  const hash = sha256(filePath);
  if (hash && KNOWN_HASHES.has(hash)) {
    threats.push({ type: 'KNOWN_MALWARE', severity: 'CRITICAL',
      desc: `Malware connu détecté (hash: ${hash.slice(0,16)}...)`, file: filePath });
  }

  // 2. Dangerous extension in temp/public paths
  if (DANGEROUS_EXTENSIONS_IN_TEMP.includes(ext)) {
    const norm = filePath.toLowerCase();
    if (norm.includes('\\temp\\') || norm.includes('\\tmp\\') ||
        norm.includes('\\public\\') || norm.includes('\\recycle')) {
      threats.push({ type: 'SUSPICIOUS_LOCATION', severity: 'HIGH',
        desc: `Exécutable dans un dossier suspect: ${path.basename(filePath)}`, file: filePath });
    }
  }

  // 3. Ransomware extension
  if (RANSOMWARE_EXTENSIONS.includes(ext)) {
    threats.push({ type: 'RANSOMWARE', severity: 'CRITICAL',
      desc: `Extension ransomware détectée: ${ext}`, file: filePath });
  }

  // 4. Entropy check (packed/encrypted = possible malware)
  if (['.exe', '.dll', '.scr'].includes(ext) && stat.size > 1024) {
    const entropy = fileEntropy(filePath);
    if (entropy > 7.2) {
      threats.push({ type: 'HIGH_ENTROPY', severity: 'MEDIUM',
        desc: `Fichier PE avec entropie élevée (${entropy.toFixed(2)}) — possible packing/chiffrement`, file: filePath });
    }
  }

  // 5. Suspicious strings scan (for scripts and small executables)
  if (['.bat', '.ps1', '.vbs', '.js', '.hta', '.cmd'].includes(ext) ||
      (stat.size < 5 * 1024 * 1024 && isPE(filePath))) {
    const content = readStrings(filePath);
    for (const pattern of SUSPICIOUS_STRINGS) {
      if (pattern.test(content)) {
        threats.push({ type: 'SUSPICIOUS_CODE', severity: 'HIGH',
          desc: `Code suspect détecté: pattern "${pattern.source.slice(0,40)}"`, file: filePath });
        break; // One per file is enough
      }
    }
  }

  return threats;
}

// ── Scan directories ──────────────────────────────────────────────────────────
function scanDirectory(dirPath, onProgress, maxDepth = 5, depth = 0) {
  const threats = [];
  if (depth > maxDepth) return threats;
  let items;
  try { items = fs.readdirSync(dirPath, { withFileTypes: true }); } catch(e) { return threats; }

  for (const item of items) {
    const full = path.join(dirPath, item.name);
    if (item.isDirectory()) {
      if (!['windows', 'system volume information', '$recycle.bin', 'node_modules', '.git']
          .includes(item.name.toLowerCase())) {
        threats.push(...scanDirectory(full, onProgress, maxDepth, depth + 1));
      }
    } else {
      if (onProgress) onProgress(full);
      threats.push(...analyzeFile(full));
    }
  }
  return threats;
}

// ── Quick Scan ────────────────────────────────────────────────────────────────
async function quickScan(onProgress) {
  const targets = [
    os.tmpdir(),
    path.join(os.homedir(), 'AppData', 'Local', 'Temp'),
    path.join(os.homedir(), 'Downloads'),
    path.join(os.homedir(), 'Desktop'),
    'C:\\Windows\\Temp',
    'C:\\Users\\Public',
    path.join(os.homedir(), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
  ];

  const threats = [];
  for (const t of targets) {
    if (fs.existsSync(t)) {
      if (onProgress) onProgress({ status: 'scanning', path: t });
      threats.push(...scanDirectory(t, (f) => onProgress && onProgress({ status: 'file', path: f }), 3));
    }
  }

  // Windows Defender integration
  const wdThreats = getWindowsDefenderThreats();
  threats.push(...wdThreats);

  return dedupeThreats(threats);
}

// ── Full Scan ─────────────────────────────────────────────────────────────────
async function fullScan(onProgress) {
  // Get all drives
  let drives = ['C:\\'];
  try {
    const out = execSync('powershell -NonInteractive -Command "Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Root | ConvertTo-Json"',
      { encoding: 'utf8', timeout: 5000 });
    const parsed = JSON.parse(out);
    drives = Array.isArray(parsed) ? parsed : [parsed];
  } catch(e) {}

  const threats = [];
  for (const drive of drives) {
    if (onProgress) onProgress({ status: 'scanning', path: drive });
    threats.push(...scanDirectory(drive,
      (f) => onProgress && onProgress({ status: 'file', path: f }), 8));
  }
  const wdThreats = getWindowsDefenderThreats();
  threats.push(...wdThreats);
  return dedupeThreats(threats);
}

// ── Custom Scan ───────────────────────────────────────────────────────────────
async function customScan(folderPath, onProgress) {
  if (!fs.existsSync(folderPath)) return [];
  const threats = scanDirectory(folderPath,
    (f) => onProgress && onProgress({ status: 'file', path: f }), 10);
  return dedupeThreats(threats);
}

// ── Windows Defender Integration ─────────────────────────────────────────────
function getWindowsDefenderThreats() {
  const threats = [];
  try {
    const out = execSync(
      `powershell -NonInteractive -Command "Get-MpThreatDetection | Select-Object ThreatName,ActionSuccess,CurrentThreatExecutionStatusID,InitialDetectionTime,Resources | ConvertTo-Json"`,
      { encoding: 'utf8', timeout: 8000 }
    );
    if (!out.trim()) return [];
    let items = JSON.parse(out);
    if (!Array.isArray(items)) items = [items];
    for (const item of items) {
      if (!item) continue;
      threats.push({
        type: 'WINDOWS_DEFENDER',
        severity: 'CRITICAL',
        desc: `Windows Defender: ${item.ThreatName || 'Menace inconnue'}`,
        file: Array.isArray(item.Resources) ? item.Resources.join(', ') : (item.Resources || ''),
        source: 'Windows Defender',
        date: item.InitialDetectionTime,
      });
    }
  } catch(e) {}
  return threats;
}

function triggerDefenderScan(scanType = 'QuickScan') {
  try {
    execSync(`powershell -NonInteractive -Command "Start-MpScan -ScanType ${scanType}"`,
      { encoding: 'utf8', timeout: 5000 });
    return true;
  } catch(e) { return false; }
}

function getDefenderStatus() {
  try {
    const out = execSync(
      `powershell -NonInteractive -Command "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,AntispywareSignatureLastUpdated,AntivirusSignatureLastUpdated | ConvertTo-Json"`,
      { encoding: 'utf8', timeout: 8000 }
    );
    return JSON.parse(out);
  } catch(e) { return null; }
}

function updateDefenderSignatures() {
  try {
    execSync(`powershell -NonInteractive -Command "Update-MpSignature"`,
      { encoding: 'utf8', timeout: 30000 });
    return true;
  } catch(e) { return false; }
}

// ── Registry Audit ────────────────────────────────────────────────────────────
function auditRegistry() {
  const threats = [];
  const runKeys = [
    'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  ];

  for (const key of runKeys) {
    try {
      const out = execSync(`powershell -NonInteractive -Command "Get-ItemProperty '${key}' | ConvertTo-Json"`,
        { encoding: 'utf8', timeout: 5000 });
      const items = JSON.parse(out);
      for (const [name, value] of Object.entries(items)) {
        if (name.startsWith('PS')) continue;
        const val = String(value).toLowerCase();
        // Check suspicious paths
        const isSuspicious =
          val.includes('\\public\\') || val.includes('\\temp\\') ||
          val.includes('\\tmp\\') || val.includes('appdata\\roaming\\') ||
          val.includes('cmd /c') || val.includes('powershell -enc') ||
          val.includes('certutil') || val.includes('wscript') ||
          val.includes('regsvr32') || val.includes('mshta');
        if (isSuspicious) {
          threats.push({
            type: 'SUSPICIOUS_AUTORUN',
            severity: 'HIGH',
            desc: `Démarrage automatique suspect: "${name}" → ${value}`,
            file: key + '\\' + name,
            canFix: true,
            fixKey: key,
            fixName: name,
          });
        }
      }
    } catch(e) {}
  }
  return threats;
}

// ── Process Audit ─────────────────────────────────────────────────────────────
function auditProcesses() {
  const threats = [];
  try {
    const out = execSync(
      `powershell -NonInteractive -Command "Get-Process | Select-Object Name,Id,Path,Company | ConvertTo-Json"`,
      { encoding: 'utf8', timeout: 8000 }
    );
    let procs = JSON.parse(out);
    if (!Array.isArray(procs)) procs = [procs];

    const nameCounts = {};
    for (const p of procs) {
      if (!p || !p.Name) continue;
      nameCounts[p.Name.toLowerCase()] = (nameCounts[p.Name.toLowerCase()] || 0) + 1;
    }

    for (const p of procs) {
      if (!p || !p.Name || !p.Path) continue;
      const name = p.Name.toLowerCase();
      const procPath = (p.Path || '').toLowerCase();

      // Check system process running from wrong location
      const systemProcs = ['svchost.exe', 'csrss.exe', 'lsass.exe', 'winlogon.exe',
                           'services.exe', 'smss.exe', 'wininit.exe', 'explorer.exe'];
      if (systemProcs.includes(name)) {
        const inSystem32 = procPath.includes('\\windows\\system32\\') ||
                           procPath.includes('\\windows\\syswow64\\');
        if (!inSystem32) {
          threats.push({
            type: 'PROCESS_MASQUERADE',
            severity: 'CRITICAL',
            desc: `Processus système "${p.Name}" hors System32 — possible injection/masquerade`,
            file: p.Path,
            pid: p.Id,
          });
        }
      }

      // Check unsigned executables in suspicious paths
      const inSuspPath = procPath.includes('\\public\\') || procPath.includes('\\temp\\') ||
                         procPath.includes('\\tmp\\') || procPath.includes('\\appdata\\roaming\\');
      if (inSuspPath && (name.endsWith('.exe'))) {
        const isTrusted = SAFE_PATHS.some(sp => p.Path && p.Path.toLowerCase().startsWith(sp.toLowerCase()));
        if (!isTrusted && !p.Company) {
          threats.push({
            type: 'SUSPICIOUS_PROCESS',
            severity: 'HIGH',
            desc: `Processus non signé dans chemin suspect: ${p.Name} (${p.Path})`,
            file: p.Path,
            pid: p.Id,
          });
        }
      }
    }
  } catch(e) {}
  return threats;
}

// ── Network Audit ─────────────────────────────────────────────────────────────
function auditNetwork() {
  const threats = [];
  try {
    const out = execSync(
      `powershell -NonInteractive -Command "Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json"`,
      { encoding: 'utf8', timeout: 8000 }
    );
    let conns = JSON.parse(out);
    if (!Array.isArray(conns)) conns = [conns];

    // Get process names
    let procMap = {};
    try {
      const pout = execSync(
        `powershell -NonInteractive -Command "Get-Process | Select-Object Id,Name,Path | ConvertTo-Json"`,
        { encoding: 'utf8', timeout: 8000 }
      );
      let procs = JSON.parse(pout);
      if (!Array.isArray(procs)) procs = [procs];
      for (const p of procs) if (p && p.Id) procMap[p.Id] = p;
    } catch(e) {}

    for (const conn of conns) {
      if (!conn || !conn.RemoteAddress) continue;
      const ip = conn.RemoteAddress;
      if (ip.startsWith('127.') || ip.startsWith('::1') || ip === '0.0.0.0') continue;

      const isSuspIP = SUSPICIOUS_IP_RANGES.some(r => r.test(ip));
      if (isSuspIP) {
        const proc = procMap[conn.OwningProcess];
        threats.push({
          type: 'SUSPICIOUS_CONNECTION',
          severity: 'HIGH',
          desc: `Connexion vers IP suspecte: ${ip}:${conn.RemotePort} — processus: ${proc?.Name || conn.OwningProcess}`,
          file: proc?.Path || String(conn.OwningProcess),
        });
      }

      // Check unsigned process with outbound connection
      const proc = procMap[conn.OwningProcess];
      if (proc?.Path) {
        const procPath = proc.Path.toLowerCase();
        const inSusp = procPath.includes('\\public\\') || procPath.includes('\\temp\\');
        if (inSusp) {
          threats.push({
            type: 'SUSPICIOUS_NETWORK_PROCESS',
            severity: 'CRITICAL',
            desc: `Processus depuis chemin suspect avec connexion réseau: ${proc.Name} → ${ip}:${conn.RemotePort}`,
            file: proc.Path,
            pid: proc.Id,
          });
        }
      }
    }
  } catch(e) {}
  return threats;
}

// ── Vulnerability Audit ───────────────────────────────────────────────────────
function auditVulnerabilities() {
  const checks = [];

  // 1. Windows Defender status
  const wdStatus = getDefenderStatus();
  if (wdStatus) {
    if (!wdStatus.AntivirusEnabled) checks.push({ id:'av', status:'FAIL', severity:'CRITICAL', label:'Antivirus Windows Defender', desc:'L\'antivirus est désactivé !' });
    else checks.push({ id:'av', status:'OK', severity:'INFO', label:'Antivirus Windows Defender', desc:'Actif et protégé' });
    if (!wdStatus.RealTimeProtectionEnabled) checks.push({ id:'rt', status:'FAIL', severity:'HIGH', label:'Protection en temps réel', desc:'La protection temps réel est désactivée !' });
    else checks.push({ id:'rt', status:'OK', severity:'INFO', label:'Protection en temps réel', desc:'Active' });
    const sigAge = wdStatus.AntivirusSignatureLastUpdated;
    if (sigAge) {
      const d = new Date(sigAge);
      const daysOld = Math.floor((Date.now()-d.getTime())/86400000);
      if (daysOld > 3) checks.push({ id:'sig', status:'WARN', severity:'MEDIUM', label:'Signatures antivirus', desc:`Signatures vieilles de ${daysOld} jours — mise à jour recommandée` });
      else checks.push({ id:'sig', status:'OK', severity:'INFO', label:'Signatures antivirus', desc:`À jour (${daysOld} jour(s))` });
    }
  }

  // 2. Firewall status
  try {
    const fw = execSync(`powershell -NonInteractive -Command "(Get-NetFirewallProfile -All | Where-Object {!$_.Enabled}) | Measure-Object | Select-Object -ExpandProperty Count"`,
      { encoding:'utf8', timeout:5000 }).trim();
    if (parseInt(fw) > 0) checks.push({ id:'fw', status:'FAIL', severity:'HIGH', label:'Pare-feu Windows', desc:`${fw} profil(s) de pare-feu désactivé(s) !` });
    else checks.push({ id:'fw', status:'OK', severity:'INFO', label:'Pare-feu Windows', desc:'Tous les profils actifs' });
  } catch(e) { checks.push({ id:'fw', status:'UNKNOWN', severity:'INFO', label:'Pare-feu Windows', desc:'Impossible de vérifier' }); }

  // 3. UAC status
  try {
    const uac = execSync(`powershell -NonInteractive -Command "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA'"`,
      { encoding:'utf8', timeout:5000 }).trim();
    if (uac === '1') checks.push({ id:'uac', status:'OK', severity:'INFO', label:'UAC (Contrôle de compte)', desc:'Activé' });
    else checks.push({ id:'uac', status:'FAIL', severity:'HIGH', label:'UAC (Contrôle de compte)', desc:'UAC désactivé — risque élevé d\'élévation de privilèges !' });
  } catch(e) {}

  // 4. Windows Update
  try {
    const wu = execSync(`powershell -NonInteractive -Command "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn"`,
      { encoding:'utf8', timeout:8000 }).trim();
    const d = new Date(wu);
    const days = Math.floor((Date.now()-d.getTime())/86400000);
    if (days > 30) checks.push({ id:'wu', status:'WARN', severity:'MEDIUM', label:'Windows Update', desc:`Dernière mise à jour il y a ${days} jours — mettez à jour Windows` });
    else checks.push({ id:'wu', status:'OK', severity:'INFO', label:'Windows Update', desc:`Dernière mise à jour il y a ${days} jour(s)` });
  } catch(e) { checks.push({ id:'wu', status:'UNKNOWN', severity:'INFO', label:'Windows Update', desc:'Impossible de vérifier' }); }

  // 5. Guest account
  try {
    const guest = execSync(`powershell -NonInteractive -Command "(Get-LocalUser -Name 'Guest').Enabled"`,
      { encoding:'utf8', timeout:5000 }).trim();
    if (guest === 'True') checks.push({ id:'guest', status:'WARN', severity:'MEDIUM', label:'Compte Invité Windows', desc:'Compte Invité activé — désactivation recommandée' });
    else checks.push({ id:'guest', status:'OK', severity:'INFO', label:'Compte Invité Windows', desc:'Désactivé' });
  } catch(e) {}

  // 6. AutoRun disabled
  try {
    const ar = execSync(`powershell -NonInteractive -Command "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue"`,
      { encoding:'utf8', timeout:5000 }).trim();
    if (ar === '255' || ar === '95') checks.push({ id:'ar', status:'OK', severity:'INFO', label:'AutoRun USB', desc:'Désactivé (bonne pratique)' });
    else checks.push({ id:'ar', status:'WARN', severity:'MEDIUM', label:'AutoRun USB', desc:'AutoRun potentiellement actif — risque d\'infection USB' });
  } catch(e) { checks.push({ id:'ar', status:'WARN', severity:'MEDIUM', label:'AutoRun USB', desc:'AutoRun potentiellement actif' }); }

  return checks;
}

// ── Quarantine ────────────────────────────────────────────────────────────────
function quarantineFile(filePath, quarantineDir) {
  try {
    if (!fs.existsSync(quarantineDir)) fs.mkdirSync(quarantineDir, { recursive: true });
    const dest = path.join(quarantineDir, path.basename(filePath) + '.quarantine');
    // Rename extension so it can't execute
    fs.renameSync(filePath, dest);
    return { success: true, dest };
  } catch(e) { return { success: false, error: e.message }; }
}

function restoreQuarantined(quarPath, originalPath) {
  try {
    fs.renameSync(quarPath, originalPath);
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
}

function deleteQuarantined(quarPath) {
  try {
    fs.unlinkSync(quarPath);
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
}

// ── Fix: Remove registry autorun ───────────────────────────────────────────────
function removeAutorun(key, name) {
  try {
    execSync(`powershell -NonInteractive -Command "Remove-ItemProperty -Path '${key}' -Name '${name}' -Force"`,
      { encoding: 'utf8', timeout: 5000 });
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
}

// ── Dedup ─────────────────────────────────────────────────────────────────────
function dedupeThreats(threats) {
  const seen = new Set();
  return threats.filter(t => {
    const key = `${t.type}:${t.file}:${t.desc}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).map((t, i) => ({ ...t, id: i + 1, timestamp: Date.now() }));
}

module.exports = {
  quickScan, fullScan, customScan,
  analyzeFile,
  getWindowsDefenderThreats, getDefenderStatus, triggerDefenderScan, updateDefenderSignatures,
  auditRegistry, auditProcesses, auditNetwork, auditVulnerabilities,
  quarantineFile, restoreQuarantined, deleteQuarantined,
  removeAutorun,
};
