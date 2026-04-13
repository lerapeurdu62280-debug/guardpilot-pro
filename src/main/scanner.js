'use strict';

const fs      = require('fs');
const fsp     = require('fs').promises;
const path    = require('path');
const os      = require('os');
const crypto  = require('crypto');
const { execSync, exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const { KNOWN_HASHES, SUSPICIOUS_STRINGS_SCRIPTS, SUSPICIOUS_STRINGS_PE,
        DANGEROUS_EXTENSIONS_IN_TEMP, RANSOMWARE_EXTENSIONS,
        SUSPICIOUS_PROCESS_PATTERNS, SUSPICIOUS_IP_RANGES, SAFE_PATHS,
        WHITELIST_PATHS, WHITELIST_HASHES } = require('./threats');
const { analyzePESections, checkDoubleExtension, checkSignature } = require('./audit_advanced');
const { loadCachedSignatures } = require('./updater');

// ── Dynamic signatures (merged with built-in on load) ────────────────────────
function buildDynamicSignatures() {
  const cached = loadCachedSignatures();
  const hashes = new Set(KNOWN_HASHES);
  const whitelist = [...WHITELIST_PATHS];
  const ransomExt = [...RANSOMWARE_EXTENSIONS];

  if (cached) {
    (cached.known_hashes || []).forEach(h => hashes.add(h));
    (cached.whitelist_paths || []).forEach(p => { if (!whitelist.includes(p)) whitelist.push(p); });
    (cached.ransomware_extensions_extra || []).forEach(e => { if (!ransomExt.includes(e)) ransomExt.push(e); });
  }
  return { hashes, whitelist, ransomExt };
}

let _sigs = null;
function getSigs() {
  if (!_sigs) _sigs = buildDynamicSignatures();
  return _sigs;
}
// Call this after a signature update to reload
function reloadSignatures() { _sigs = null; }

// Check if a path is whitelisted (known legitimate software)
function isWhitelisted(filePath) {
  if (!filePath) return false;
  const lower = filePath.toLowerCase();
  return getSigs().whitelist.some(w => lower.includes(w.toLowerCase()));
}

// ── Utilities ─────────────────────────────────────────────────────────────────
async function sha256(filePath) {
  try {
    const buf = await fsp.readFile(filePath);
    return crypto.createHash('sha256').update(buf).digest('hex');
  } catch(e) { return null; }
}

async function fileEntropy(filePath) {
  try {
    const buf = await fsp.readFile(filePath);
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

async function isPE(filePath) {
  try {
    const fd = await fsp.open(filePath, 'r');
    const buf = Buffer.alloc(2);
    await fd.read(buf, 0, 2, 0);
    await fd.close();
    return buf[0] === 0x4D && buf[1] === 0x5A; // MZ header
  } catch(e) { return false; }
}

async function readStrings(filePath, minLen = 6) {
  try {
    const buf = await fsp.readFile(filePath);
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

// Determine if a file is in a truly suspicious location (where malware hides)
function isInSuspiciousLocation(filePath) {
  const norm = filePath.toLowerCase();
  return (
    norm.includes('\\temp\\') ||
    norm.includes('\\tmp\\') ||
    norm.includes('\\windows\\temp') ||
    (norm.includes('\\public\\') && !norm.includes('\\public\\desktop')) ||
    norm.includes('\\recycle') ||
    norm.includes('\\$recycle.bin')
  );
}

// ── Scan a single file ────────────────────────────────────────────────────────
async function analyzeFile(filePath) {
  // Skip whitelisted apps immediately
  if (isWhitelisted(filePath)) return [];

  const threats = [];
  const ext = path.extname(filePath).toLowerCase();
  const inSuspLoc = isInSuspiciousLocation(filePath);
  let stat;
  try { stat = fs.statSync(filePath); } catch(e) { return []; }
  if (stat.size > 50 * 1024 * 1024) return []; // Skip > 50MB
  if (stat.size === 0) return [];

  // 1. Hash check — always reliable, always run
  const hash = await sha256(filePath);
  if (hash && WHITELIST_HASHES.has(hash)) return []; // Safe hash, skip
  if (hash && getSigs().hashes.has(hash)) {
    threats.push({ type: 'KNOWN_MALWARE', severity: 'CRITICAL',
      desc: `Malware connu détecté (hash: ${hash.slice(0,16)}...)`, file: filePath });
    return threats; // No need to check further
  }

  // 2. Double extension / RTL name trick — always flag
  const dblExt = checkDoubleExtension(filePath);
  if (dblExt.detected) {
    threats.push({ type: 'DOUBLE_EXTENSION', severity: 'HIGH',
      desc: `Technique de camouflage: "${dblExt.name}" (${dblExt.trick || 'double extension'})`, file: filePath });
  }

  // 3. Ransomware extension — always flag regardless of location
  if (getSigs().ransomExt.includes(ext)) {
    threats.push({ type: 'RANSOMWARE', severity: 'CRITICAL',
      desc: `Extension ransomware détectée: ${ext}`, file: filePath });
    return threats;
  }

  // 4. Dangerous extension in suspicious location
  if (DANGEROUS_EXTENSIONS_IN_TEMP.includes(ext) && inSuspLoc) {
    threats.push({ type: 'SUSPICIOUS_LOCATION', severity: 'HIGH',
      desc: `Exécutable dans dossier suspect: ${path.basename(filePath)}`, file: filePath });
  }

  // 5. Entropy + PE sections — only in suspicious locations
  if (['.exe', '.dll', '.scr'].includes(ext) && stat.size > 1024 && inSuspLoc) {
    const entropy = await fileEntropy(filePath);
    if (entropy > 7.2) {
      threats.push({ type: 'HIGH_ENTROPY', severity: 'MEDIUM',
        desc: `PE avec entropie élevée (${entropy.toFixed(2)}) dans dossier suspect — possible packing/chiffrement`, file: filePath });
    }

    // PE sections analysis (packer detection)
    const suspSections = analyzePESections(filePath);
    if (suspSections) {
      threats.push({ type: 'PACKED_EXECUTABLE', severity: 'MEDIUM',
        desc: `Exécutable packé détecté dans dossier suspect: sections ${suspSections.join(', ')}`, file: filePath });
    }
  }

  // 6. String pattern scan
  const isScript = ['.bat', '.ps1', '.vbs', '.js', '.hta', '.cmd'].includes(ext);
  const peCheck = ['.exe', '.dll', '.scr'].includes(ext) && stat.size < 5 * 1024 * 1024;
  const isPEFile = peCheck ? await isPE(filePath) : false;

  if (isScript) {
    const content = await readStrings(filePath);
    for (const pattern of SUSPICIOUS_STRINGS_SCRIPTS) {
      if (pattern.test(content)) {
        threats.push({ type: 'SUSPICIOUS_CODE', severity: 'HIGH',
          desc: `Script suspect: pattern "${pattern.source.slice(0,40)}"`, file: filePath });
        break;
      }
    }
  } else if (isPEFile && inSuspLoc) {
    const content = await readStrings(filePath);
    for (const pattern of SUSPICIOUS_STRINGS_PE) {
      if (pattern.test(content)) {
        threats.push({ type: 'SUSPICIOUS_CODE', severity: 'HIGH',
          desc: `Code suspect dans emplacement dangereux: "${pattern.source.slice(0,40)}"`, file: filePath });
        break;
      }
    }
  }

  return threats;
}

// ── Scan directories (async with yields to keep UI responsive) ────────────────
async function scanDirectory(dirPath, onProgress, maxDepth = 5, depth = 0) {
  const threats = [];
  if (depth > maxDepth) return threats;
  let items;
  try { items = fs.readdirSync(dirPath, { withFileTypes: true }); } catch(e) { return threats; }

  const SKIP_DIRS = ['windows', 'system volume information', '$recycle.bin', 'node_modules', '.git', 'winsxs', 'servicing'];
  let count = 0;

  for (const item of items) {
    const full = path.join(dirPath, item.name);
    if (item.isDirectory()) {
      if (!SKIP_DIRS.includes(item.name.toLowerCase())) {
        const sub = await scanDirectory(full, onProgress, maxDepth, depth + 1);
        threats.push(...sub);
      }
    } else {
      if (onProgress) onProgress(full);
      threats.push(...await analyzeFile(full));
    }
    // Yield every 50 files so the worker event loop stays responsive
    if (++count % 50 === 0) {
      await new Promise(resolve => setImmediate(resolve));
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
      threats.push(...await scanDirectory(t, (f) => onProgress && onProgress({ status: 'file', path: f }), 3));
    }
  }

  // Windows Defender integration
  const wdThreats = getWindowsDefenderThreats();
  threats.push(...wdThreats);

  return dedupeThreats(threats);
}

// ── Full Scan ─────────────────────────────────────────────────────────────────
async function fullScan(onProgress) {
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
    threats.push(...await scanDirectory(drive,
      (f) => onProgress && onProgress({ status: 'file', path: f }), 8));
  }
  const wdThreats = getWindowsDefenderThreats();
  threats.push(...wdThreats);
  return dedupeThreats(threats);
}

// ── Custom Scan ───────────────────────────────────────────────────────────────
async function customScan(folderPath, onProgress) {
  if (!fs.existsSync(folderPath)) return [];
  const threats = await scanDirectory(folderPath,
    (f) => onProgress && onProgress({ status: 'file', path: f }), 10);
  return dedupeThreats(threats);
}

// ── Windows Defender Integration ─────────────────────────────────────────────
function getWindowsDefenderThreats() {
  const threats = [];

  // 1. Active threats (IsActive = true) → CRITICAL
  try {
    const out = execSync(
      `powershell -NonInteractive -Command "Get-MpThreat | Where-Object {$_.IsActive -eq $true} | Select-Object ThreatName,Resources | ConvertTo-Json"`,
      { encoding: 'utf8', timeout: 8000 }
    );
    if (out.trim()) {
      let items = JSON.parse(out);
      if (!Array.isArray(items)) items = [items];
      for (const item of items) {
        if (!item) continue;
        const res = Array.isArray(item.Resources) ? item.Resources.join(', ') : (item.Resources || '');
        threats.push({
          type: 'WINDOWS_DEFENDER',
          severity: 'CRITICAL',
          desc: `Windows Defender [ACTIF]: ${item.ThreatName || 'Menace active'}`,
          file: res,
          source: 'Windows Defender',
        });
      }
    }
  } catch(e) {}

  // 2. Resolved threats (IsActive = false) → MEDIUM, labelled as already handled
  try {
    const out = execSync(
      `powershell -NonInteractive -Command "Get-MpThreat | Where-Object {$_.IsActive -eq $false} | Select-Object ThreatName,Resources | ConvertTo-Json"`,
      { encoding: 'utf8', timeout: 8000 }
    );
    if (out.trim()) {
      let items = JSON.parse(out);
      if (!Array.isArray(items)) items = [items];
      for (const item of items) {
        if (!item) continue;
        const res = Array.isArray(item.Resources) ? item.Resources.join(', ') : (item.Resources || '');
        threats.push({
          type: 'WINDOWS_DEFENDER_HISTORY',
          severity: 'MEDIUM',
          desc: `Windows Defender [traité]: ${item.ThreatName || 'Menace inconnue'}`,
          file: res,
          source: 'Windows Defender',
        });
      }
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
      if (isWhitelisted(p.Path) || isWhitelisted(p.Name)) continue; // Skip known safe apps
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

// ── Vulnerability Audit (fully async — no main-thread freeze) ─────────────────
async function auditVulnerabilities() {
  const checks = [];

  async function psRun(cmd, timeout = 6000) {
    try {
      const { stdout } = await execAsync(
        `powershell -NonInteractive -Command "${cmd.replace(/"/g, '\\"')}"`,
        { encoding: 'utf8', timeout }
      );
      return stdout.trim();
    } catch(e) { return null; }
  }

  // 1. GuardPilot engine status (remplace Windows Defender)
  try {
    const sigs = loadCachedSignatures();
    const hashCount = sigs ? (sigs.known_hashes || []).length : getSigs().hashes.size;
    const version   = sigs ? (sigs.version || '—') : '—';
    checks.push({ id:'gp', status:'OK', severity:'INFO', label:'Moteur GuardPilot',
      desc:`Actif — ${hashCount} signatures chargées (v${version})` });
  } catch(e) {
    checks.push({ id:'gp', status:'WARN', severity:'MEDIUM', label:'Moteur GuardPilot',
      desc:'Impossible de charger les signatures' });
  }

  // 2. Firewall status
  const fw = await psRun("(Get-NetFirewallProfile -All | Where-Object {!$_.Enabled}) | Measure-Object | Select-Object -ExpandProperty Count");
  if (fw === null) {
    checks.push({ id:'fw', status:'UNKNOWN', severity:'INFO', label:'Pare-feu Windows', desc:'Impossible de vérifier' });
  } else if (parseInt(fw) > 0) {
    checks.push({ id:'fw', status:'FAIL', severity:'HIGH', label:'Pare-feu Windows', desc:`${fw} profil(s) de pare-feu désactivé(s) !` });
  } else {
    checks.push({ id:'fw', status:'OK', severity:'INFO', label:'Pare-feu Windows', desc:'Tous les profils actifs' });
  }

  // 3. UAC status
  const uac = await psRun("Get-ItemPropertyValue 'HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System' -Name 'EnableLUA'");
  if (uac === '1') checks.push({ id:'uac', status:'OK', severity:'INFO', label:'UAC (Contrôle de compte)', desc:'Activé' });
  else if (uac !== null) checks.push({ id:'uac', status:'FAIL', severity:'HIGH', label:'UAC (Contrôle de compte)', desc:'UAC désactivé — risque élevé d\'élévation de privilèges !' });

  // 4. Windows Update (dernier hotfix — rapide, sans WUApiLib)
  const wu = await psRun("(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn", 10000);
  if (wu) {
    const d = new Date(wu);
    if (!isNaN(d)) {
      const days = Math.floor((Date.now()-d.getTime())/86400000);
      if (days > 30) checks.push({ id:'wu', status:'WARN', severity:'MEDIUM', label:'Windows Update', desc:`Dernière mise à jour il y a ${days} jours — mettez à jour Windows` });
      else checks.push({ id:'wu', status:'OK', severity:'INFO', label:'Windows Update', desc:`Dernière mise à jour il y a ${days} jour(s)` });
    }
  } else {
    checks.push({ id:'wu', status:'UNKNOWN', severity:'INFO', label:'Windows Update', desc:'Impossible de vérifier' });
  }

  // 5. Guest account
  const guest = await psRun("(Get-LocalUser -Name 'Guest').Enabled");
  if (guest === 'True') checks.push({ id:'guest', status:'WARN', severity:'MEDIUM', label:'Compte Invité Windows', desc:'Compte Invité activé — désactivation recommandée' });
  else if (guest === 'False') checks.push({ id:'guest', status:'OK', severity:'INFO', label:'Compte Invité Windows', desc:'Désactivé' });

  // 6. AutoRun
  const ar = await psRun("Get-ItemPropertyValue 'HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer' -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue");
  if (ar === '255' || ar === '95') checks.push({ id:'ar', status:'OK', severity:'INFO', label:'AutoRun USB', desc:'Désactivé (bonne pratique)' });
  else checks.push({ id:'ar', status:'WARN', severity:'MEDIUM', label:'AutoRun USB', desc:'AutoRun potentiellement actif — risque d\'infection USB' });

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
  reloadSignatures,
};
