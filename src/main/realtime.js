'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { analyzeFile } = require('./scanner');
const { DANGEROUS_EXTENSIONS_IN_TEMP, WHITELIST_PATHS } = require('./threats');

function isWhitelisted(p) {
  const lower = (p||'').toLowerCase();
  return WHITELIST_PATHS.some(w => lower.includes(w.toLowerCase()));
}

let watchers = [];
let active   = false;
let onThreat = null;
let onActivity = null;

const WATCH_DIRS = [
  os.tmpdir(),
  path.join(os.homedir(), 'AppData', 'Local', 'Temp'),
  path.join(os.homedir(), 'Downloads'),
  path.join(os.homedir(), 'Desktop'),
  'C:\\Windows\\Temp',
  path.join(os.homedir(), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
];

function startRealtime(threatCallback, activityCallback) {
  if (active) return;
  active = true;
  onThreat = threatCallback;
  onActivity = activityCallback;

  for (const dir of WATCH_DIRS) {
    if (!fs.existsSync(dir)) continue;
    try {
      const watcher = fs.watch(dir, { recursive: false }, (eventType, filename) => {
        if (!filename) return;
        const fullPath = path.join(dir, filename);
        const ext = path.extname(filename).toLowerCase();

        if (onActivity) onActivity({ event: eventType, path: fullPath, time: Date.now() });

        // Immediate alert for dangerous extensions
        if (DANGEROUS_EXTENSIONS_IN_TEMP.includes(ext) && !isWhitelisted(fullPath)) {
          setTimeout(() => {
            if (!fs.existsSync(fullPath)) return;
            if (isWhitelisted(fullPath)) return;
            const threats = analyzeFile(fullPath);
            if (threats.length > 0 && onThreat) {
              for (const t of threats) onThreat({ ...t, realtime: true });
            } else if (onThreat) {
              // Still flag suspicious extension even if no pattern match
              onThreat({
                type: 'REALTIME_ALERT',
                severity: 'MEDIUM',
                desc: `Nouveau fichier exécutable détecté: ${filename}`,
                file: fullPath,
                realtime: true,
                timestamp: Date.now(),
              });
            }
          }, 500);
        }
      });
      watchers.push(watcher);
    } catch(e) {}
  }
}

function stopRealtime() {
  active = false;
  for (const w of watchers) { try { w.close(); } catch(e) {} }
  watchers = [];
  onThreat = null;
  onActivity = null;
}

function isActive() { return active; }

module.exports = { startRealtime, stopRealtime, isActive };
