'use strict';

const https = require('https');
const fs    = require('fs');
const path  = require('path');
const os    = require('os');

// GitHub API endpoint — bypasses CDN cache, always returns latest commit
const SIGNATURES_API_URL = 'https://api.github.com/repos/lerapeurdu62280-debug/guardpilot-pro/contents/signatures.json';
const LOCAL_CACHE    = path.join(os.homedir(), 'AppData', 'Local', 'GuardPilot', 'signatures.json');

function ensureCacheDir() {
  const dir = path.dirname(LOCAL_CACHE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// Fetch raw HTTPS, returns Promise<string>
function fetchRaw(url, options = {}) {
  return new Promise((resolve, reject) => {
    const opts = Object.assign({ timeout: 10000, headers: { 'User-Agent': 'GuardPilot' } }, options);
    const req = https.get(url, opts, (res) => {
      // Follow redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchRaw(res.headers.location, options).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

// Download latest signatures from GitHub API (no CDN cache) and save locally
async function updateSignatures() {
  // GitHub API returns { content: base64, ... }
  const raw = await fetchRaw(SIGNATURES_API_URL);
  const meta = JSON.parse(raw);
  const content = Buffer.from(meta.content, 'base64').toString('utf8');
  const sigs = JSON.parse(content);
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
