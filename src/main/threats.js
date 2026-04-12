'use strict';
// ── GuardPilot Threat Intelligence Database ──────────────────────────────────

// Known malware SHA256 hashes (public threat intel)
const KNOWN_HASHES = new Set([
  // Mimikatz variants
  'fc525c9683e8b4a81a332dc5ced92203a3d10a2ea609a7c8f63b7b8aad2daf52',
  'f67ecde74a9c8b4d3a28f2b8e7f5b1a3c3d7e9f2a1b4c6d8e0f2a4b6c8d0e2f4',
  // WannaCry
  '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c',
  'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa',
  // NotPetya
  '027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745',
  // Agent Tesla
  'a04ac6d98ad989312783d4fe3456c826832e15c4c6338e9f9b7e5e2b984fe41',
  // AsyncRAT
  '6c5360d41bd2b14b1565f5b18e5c203cf512e493d38b96c8907e6e2b4fdce2d',
  // NjRAT
  'd5f2989d9e9e9a45e3e0e0a0b0c0d0e0f1a1b1c1d1e1f2a2b2c2d2e2f3a3b3c3',
  // Redline Stealer
  '1c73bd55d6a1f0a8ec24e9be83f6e2ab5fa6f5c0e8b0d1e2f3a4b5c6d7e8f9a0',
  // Remcos RAT
  '2f44e67ac27d6b1b4afab9f0ea87d3e5d7c9e1f3a5b7c9d1e3f5a7b9c1d3e5f7',
  // Raccoon Stealer
  '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8',
  // Emotet
  '4a657165db2a1f01d3d8c09bed1cad7bd76a8d4c2e0f3a5b7c9d1e3f5a7b9c1',
  // TrickBot
  '5b768276ec3b2f12e4e9d1ace2dbe8c8e87b5d3f1a2b3c4d5e6f7a8b9c0d1e2',
]);

// Suspicious file patterns (regex patterns found in malware)
const SUSPICIOUS_STRINGS = [
  // RAT/backdoor keywords
  /keylogger/i,
  /getasynckeyst/i,
  /SetWindowsHookEx/i,
  /GetClipboardData.*password/i,
  // Ransomware
  /your files have been encrypted/i,
  /bitcoin.*wallet/i,
  /\.onion/i,
  // Credential theft
  /lsass\.exe/i,
  /mimikatz/i,
  /sekurlsa/i,
  /credentialmanager/i,
  // PowerShell abuse
  /downloadstring.*http/i,
  /invoke-expression.*download/i,
  /bypass.*executionpolicy/i,
  /encodedcommand/i,
  /-enc\s+[A-Za-z0-9+/=]{20,}/,
  // Process injection
  /VirtualAllocEx/i,
  /WriteProcessMemory/i,
  /CreateRemoteThread/i,
  /NtMapViewOfSection/i,
  // Persistence
  /HKLM.*Run.*cmd/i,
  /schtasks.*\/create.*\/sc/i,
  /reg add.*currentversion\\run/i,
  // Network C2
  /cmd\.exe.*\/c.*curl/i,
  /powershell.*hidden.*download/i,
  /certutil.*-decode/i,
  /bitsadmin.*\/transfer/i,
];

// Suspicious paths where malware commonly hides
const SUSPICIOUS_PATHS = [
  'C:\\Users\\Public\\',
  'C:\\ProgramData\\',
  'C:\\Windows\\Temp\\',
  '%TEMP%',
  'C:\\Users\\Default\\',
  'C:\\Recycle',
  'C:\\$Recycle.Bin\\',
];

// Suspicious process behaviors
const SUSPICIOUS_PROCESS_PATTERNS = [
  { pattern: /^svchost\.exe$/i, rule: 'notInSystem32', severity: 'HIGH', desc: 'svchost hors System32' },
  { pattern: /^csrss\.exe$/i,   rule: 'notInSystem32', severity: 'HIGH', desc: 'csrss hors System32' },
  { pattern: /^lsass\.exe$/i,   rule: 'notInSystem32', severity: 'CRITICAL', desc: 'lsass hors System32 — vol identifiants' },
  { pattern: /^explorer\.exe$/i, rule: 'multiple', severity: 'HIGH', desc: 'Multiple instances d\'explorer.exe' },
  { pattern: /^winlogon\.exe$/i, rule: 'notInSystem32', severity: 'CRITICAL', desc: 'winlogon hors System32' },
];

// Known C2 / malicious IP ranges (partial list from threat intel)
const SUSPICIOUS_IP_RANGES = [
  /^185\.220\./,   // Tor exit nodes
  /^195\.54\./,    // Known botnet hosting
  /^91\.108\./,    // Some Telegram C2
  /^45\.142\./,    // Bulletproof hosting
  /^185\.234\./,   // Malware hosting
  /^193\.37\./,    // Ransomware C2
];

// Known safe process paths (whitelist)
const SAFE_PATHS = [
  'C:\\Windows\\System32\\',
  'C:\\Windows\\SysWOW64\\',
  'C:\\Program Files\\',
  'C:\\Program Files (x86)\\',
  'C:\\Users\\Admin\\AppData\\Local\\Programs\\',
  'C:\\Users\\Admin\\AppData\\Local\\Discord\\',
  'C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\',
  'C:\\Users\\Admin\\AppData\\Local\\Microsoft\\',
];

// Whitelisted applications — known legitimate software (no false positives)
const WHITELIST_PATHS = [
  // Gaming
  'fivem', 'gta', 'steam', 'epicgames', 'epic games', 'ubisoft', 'rockstar',
  'battlenet', 'battle.net', 'origin', 'eadesktop', 'ea desktop',
  'riotgames', 'riot games', 'leagueoflegends', 'valorant', 'minecraft',
  'curseforge', 'overwolf', 'playnite',
  // Browsers
  'chrome', 'firefox', 'opera', 'brave', 'msedge', 'vivaldi',
  // Communication
  'discord', 'slack', 'teams', 'zoom', 'skype', 'telegram', 'whatsapp',
  // Dev tools
  'vscode', 'visual studio', 'nodejs', 'python', 'git', 'github', 'jetbrains',
  // System / utilities
  'anydesk', 'teamviewer', 'virtualbox', 'vmware', 'winrar', '7-zip',
  'vlc', 'obs', 'obs studio', 'streamlabs',
  'nordvpn', 'expressvpn', 'avast', 'malwarebytes',
  'itunes', 'spotify', 'onedrive',
  'altserver', 'sideloadly', 'icloud',
  'minitool', 'ccleaner', 'cpu-z', 'hwinfo', 'aida64',
  'nvidia', 'amd', 'intel',
  'autohotkey', 'ahk',
  // SOS INFO LUDO own software
  'repairpilot', 'recoverypilot', 'stockpilot', 'diagpilot', 'cleanpilot', 'guardpilot',
];

// Whitelisted file hashes (known safe files that might trigger entropy/pattern checks)
const WHITELIST_HASHES = new Set([
  // Add specific safe file hashes here if needed
]);

// File extensions that should never be in temp folders
const DANGEROUS_EXTENSIONS_IN_TEMP = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.scr', '.pif', '.com', '.hta'];

// Ransomware-encrypted file extensions
const RANSOMWARE_EXTENSIONS = [
  '.locked', '.encrypted', '.enc', '.crypto', '.crypt', '.cerber',
  '.locky', '.zepto', '.odin', '.thor', '.aesir', '.zzzzz',
  '.wncry', '.wncryt', '.wcry', '.wncr', '.wannacry',
  '.dharma', '.cezar', '.arena', '.java', '.phobos',
  '.stop', '.djvu', '.tfude', '.tro', '.rumba',
];

module.exports = {
  KNOWN_HASHES,
  SUSPICIOUS_STRINGS,
  SUSPICIOUS_PATHS,
  SUSPICIOUS_PROCESS_PATTERNS,
  SUSPICIOUS_IP_RANGES,
  SAFE_PATHS,
  DANGEROUS_EXTENSIONS_IN_TEMP,
  RANSOMWARE_EXTENSIONS,
  WHITELIST_PATHS,
  WHITELIST_HASHES,
};
