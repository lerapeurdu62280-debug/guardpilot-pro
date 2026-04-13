'use strict';

const https = require('https');
const fs    = require('fs');
const path  = require('path');
const os    = require('os');

const SIGNATURES_URL = 'https://raw.githubusercontent.com/lerapeurdu62280-debug/guardpilot-pro/main/signatures.json';
const LOCAL_CACHE    = path.join(os.homedir(), 'AppData', 'Local', 'GuardPilot', 'signatures.json');

function ensureCacheDir() {
  const dir = path.dirname(LOCAL_CACHE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// Fetch JSON from URL, returns Promise<object>
function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: 10000 }, (res) => {
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { reject(new Error('Invalid JSON')); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

// Download latest signatures from GitHub and save locally
async function updateSignatures() {
  const sigs = await fetchJSON(SIGNATURES_URL);
  ensureCacheDir();
  fs.writeFileSync(LOCAL_CACHE, JSON.stringify(sigs, null, 2), 'utf8');
  return sigs;
}

// Load cached signatures (returns null if not available)
function loadCachedSignatures() {
  try {
    if (!fs.existsSync(LOCAL_CACHE)) return null;
    return JSON.parse(fs.readFileSync(LOCAL_CACHE, 'utf8'));
  } catch(e) { return null; }
}

// Get current signatures info (version + date)
function getSignaturesInfo() {
  const cached = loadCachedSignatures();
  if (!cached) return { version: 'Base intégrée', updated: null, source: 'builtin' };
  return {
    version: cached.version || '—',
    updated: cached.updated || null,
    source: 'cached',
    hashCount: (cached.known_hashes || []).length,
  };
}

module.exports = { updateSignatures, loadCachedSignatures, getSignaturesInfo };
