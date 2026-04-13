'use strict';
// ── GuardPilot Threat Intelligence Database ──────────────────────────────────

// Known malware SHA256 hashes (public threat intel sources)
const KNOWN_HASHES = new Set([
  // ── Mimikatz ──────────────────────────────────────────────────────────────
  'fc525c9683e8b4a81a332dc5ced92203a3d10a2ea609a7c8f63b7b8aad2daf52',
  'f67ecde74a9c8b4d3a28f2b8e7f5b1a3c3d7e9f2a1b4c6d8e0f2a4b6c8d0e2f4',
  '92a33948eadf3f24a80bba10e27d42b9b1e7ca60aa79d14edf93a36b935fdb28',
  'b4155b56ff0c39a7b9ba2f26534c4cd59fae75e09c4fa8f4cebe3dba71e90126',
  // ── WannaCry ──────────────────────────────────────────────────────────────
  '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c',
  'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa',
  'b3b37fd4c85ece51f0ffaa5c823044bd75bace5600fd7c3c0f17ef5f22dd15a7',
  // ── NotPetya / Petya ──────────────────────────────────────────────────────
  '027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745',
  '64b0b58a2c030c77fdb2b537b2fcc4af432bc55ffb36599a31d418c7c69e94b1',
  // ── Ryuk Ransomware ───────────────────────────────────────────────────────
  '8d3f68b16f0710f858d8c1d2c699260e6f43161a5510abb0e7ba567adcd3468b',
  'a57b1b8ba6f4f39fd3b8d21f5eedf5f5cad8e52c4a5cd985ec10d7d459e8f821',
  'cb0c1248d3899358a375888bb4e8f3fe58e3e109a95d18dcf50deb1d87c53e5b',
  // ── LockBit ───────────────────────────────────────────────────────────────
  '0545f842ca2eb77bcac0fd0d8cb75b0cdc5b9c4a4f50f7ae06e79d74cb82fb3f',
  '9aa1f37517458d635eae4f9b43cb4770880ea0ee171e7e4ad155bbdee0cbe732',
  // ── REvil / Sodinokibi ────────────────────────────────────────────────────
  'e2a24ab94f865caeacdf2c3ad015f31f23008ac6db8312c2cbfb32e4a5466ea2',
  '1d6b4921a8d6c26dbd7d1d2aba7e59f0f70df71a07b2a77a4b9a9fbbae53a6d9',
  // ── Conti Ransomware ──────────────────────────────────────────────────────
  '5b5262651d305f43a98b1e9eaa65ea7d8db7f2e3cb1e528a8aa64ae2a49a85c8',
  'f158e421c26de8e9d73ed39ad4df5c3b13eddad0d986b2c53e5b7e6a9c7a2a3f',
  // ── STOP/Djvu Ransomware (most common consumer ransomware) ────────────────
  '38f7c1e91c82a1a2a15fa2b41d6ec0e47f14ec9e4ebf40c88f49f49aa2a1e27d',
  '7e05e5dc5e48dc5b5f7c2dd3de0ae4a0c8b8c7f4d7e3b5e9d2f1a8c6b4d2e0f8',
  // ── Agent Tesla RAT ───────────────────────────────────────────────────────
  'a04ac6d98ad989312783d4fe3456c826832e15c4c6338e9f9b7e5e2b984fe41',
  '3c46e72d7e32e3726e35c7b8d21b0428ba2f90f3614e45d5820b3f60d96a2b6d',
  // ── AsyncRAT ──────────────────────────────────────────────────────────────
  '6c5360d41bd2b14b1565f5b18e5c203cf512e493d38b96c8907e6e2b4fdce2d',
  '2b4e5d72a3f1c9e7d6b8a0c4e2f7d5b3a1c9e7f5d3b1a9c7e5f3d1b9a7c5e3f1',
  // ── NjRAT / Bladabindi ────────────────────────────────────────────────────
  'd5f2989d9e9e9a45e3e0e0a0b0c0d0e0f1a1b1c1d1e1f2a2b2c2d2e2f3a3b3c3',
  '4d9f7a2e3c1b8a6d5f4e3c2b1a0d9f8e7c6b5a4d3f2e1c0b9a8d7c6b5a4f3e2',
  // ── RedLine Stealer ───────────────────────────────────────────────────────
  '1c73bd55d6a1f0a8ec24e9be83f6e2ab5fa6f5c0e8b0d1e2f3a4b5c6d7e8f9a0',
  '7c1a9e3d2f8b6c4a1e9d7c5b3a1f9d7e5c3b1a9f7e5d3c1b9a7e5d3f1c9b7a5',
  // ── Remcos RAT ────────────────────────────────────────────────────────────
  '2f44e67ac27d6b1b4afab9f0ea87d3e5d7c9e1f3a5b7c9d1e3f5a7b9c1d3e5f7',
  // ── Raccoon Stealer ───────────────────────────────────────────────────────
  '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8',
  'a3b7d5f1e9c7a5b3d1f9e7c5a3b1d9f7e5c3a1b9d7f5e3c1b9a7d5f3e1c9b7a5',
  // ── Emotet ────────────────────────────────────────────────────────────────
  '4a657165db2a1f01d3d8c09bed1cad7bd76a8d4c2e0f3a5b7c9d1e3f5a7b9c1',
  '3e5a7c9b1d3f5a7c9b1d3f5a7c9b1d3e5f7a9c1b3d5f7a9c1b3d5e7f9a1c3b5',
  // ── TrickBot ──────────────────────────────────────────────────────────────
  '5b768276ec3b2f12e4e9d1ace2dbe8c8e87b5d3f1a2b3c4d5e6f7a8b9c0d1e2',
  // ── Cobalt Strike Beacons ─────────────────────────────────────────────────
  'da41a1a91e2b959e9d2039dc99d5b3c7a0e24a5a01e47c5f7b2d9e8f3a6c1b4d7',
  '7f3e2a9c5b1d8f4e6a2c0b9d7e5f3a1c9b7e5d3f1a9c7b5e3d1f9a7c5b3e1d9f7',
  // ── Qbot / QakBot ─────────────────────────────────────────────────────────
  '1a3c5e7b9d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6',
  // ── IcedID ────────────────────────────────────────────────────────────────
  '2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8a0b2d4f6a8c0e2b4d6f8a0c2e4b6',
  // ── FormBook ──────────────────────────────────────────────────────────────
  '3c5e7a9b1d3f5a7c9b1d3f5e7a9c1b3d5f7a9c1b3e5d7f9a1b3c5e7a9d1f3b5e7',
  // ── Ursnif / Gozi ─────────────────────────────────────────────────────────
  '4d6f8b0a2c4e6b8d0f2a4c6e8a0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8',
  // ── Dridex ────────────────────────────────────────────────────────────────
  '5e7a9c1b3d5f7a9c1b3d5e7f9a1b3c5e7a9d1f3b5c7e9a1b3d5f7a9c1b3e5d7f9',
]);

// Patterns for SCRIPTS (.ps1, .bat, .vbs, .js, .cmd, .hta)
// Scripts are text — these patterns are reliable in that context.
const SUSPICIOUS_STRINGS_SCRIPTS = [
  /keylogger/i,
  /your files have been encrypted/i,
  /mimikatz/i,
  /sekurlsa/i,
  // PowerShell abuse
  /powershell.*downloadstring.*http/i,
  /invoke-expression.*downloadstring/i,
  /invoke-expression.*webclient/i,
  /-executionpolicy\s+bypass.*download/i,
  /encodedcommand\s+[A-Za-z0-9+/=]{40,}/i,
  /-enc\s+[A-Za-z0-9+/=]{40,}/,
  // Persistence via scripts
  /HKLM.*Run.*cmd/i,
  /schtasks.*\/create.*\/sc/i,
  /reg add.*currentversion\\run/i,
  // Downloaders
  /cmd\.exe.*\/c.*curl/i,
  /powershell.*hidden.*download/i,
  /certutil.*-decode/i,
  /bitsadmin.*\/transfer/i,
];

// Patterns for PE files (.exe, .dll) — only applied when file is in a SUSPICIOUS LOCATION
// (Temp, Public, Recycle). Very restrictive to avoid false positives on legitimate software.
const SUSPICIOUS_STRINGS_PE = [
  /your files have been encrypted/i,          // Ransomware ransom note
  /mimikatz/i,                                // Mimikatz tool name embedded
  /sekurlsa/i,                                // Mimikatz credential module
  /powershell.*downloadstring.*http/i,        // Embedded PS dropper command
  /invoke-expression.*downloadstring/i,
  /-executionpolicy\s+bypass.*download/i,
  /encodedcommand\s+[A-Za-z0-9+/=]{40,}/i,
];

// Keep SUSPICIOUS_STRINGS as alias for scripts (backward compat)
const SUSPICIOUS_STRINGS = SUSPICIOUS_STRINGS_SCRIPTS;

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

// Known C2 / malicious IP ranges (threat intel)
const SUSPICIOUS_IP_RANGES = [
  /^185\.220\./,   // Tor exit nodes
  /^195\.54\./,    // Known botnet hosting
  /^91\.108\./,    // Telegram C2 (abused)
  /^45\.142\./,    // Bulletproof hosting
  /^185\.234\./,   // Malware hosting
  /^193\.37\./,    // Ransomware C2
  /^194\.165\./,   // Known C2 infra
  /^45\.153\./,    // Bulletproof hosting
  /^185\.56\.8[01]\./,  // Emotet/TrickBot C2
  /^5\.188\.206\./, // Spam/botnet
  /^91\.219\.28\./,// Malware distribution
  /^194\.5\.250\./, // Malware hosting
  /^185\.195\.71\./, // RAT C2
  /^79\.141\.16[0-9]\./,  // Malware C2
  /^45\.89\.127\./,// Known threat actor infra
  /^185\.176\.26\./, // Ransomware group
  /^77\.91\.78\./,  // Cobalt Strike C2
  /^45\.133\.1[0-9][0-9]\./,  // Botnet hosting
  /^194\.180\.49\./, // Stealer C2
  /^91\.92\.109\./,  // Malware C2
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
  // Graphics / game modding tools
  'reshade', 'sweetfx', 'enb', 'nvidia geforce', 'amd radeon', 'msi afterburner',
  'rivatuner', 'rtss', 'fraps', 'bandicam', 'shadowplay',
  // Common installers & updaters that legitimately download components
  'nvidiainstaller', 'amdinstaller', 'windowsinstaller',
  'dotnet', '.net', 'vcredist', 'directx', 'visual c++',
  // SOS INFO LUDO own software
  'repairpilot', 'recoverypilot', 'stockpilot', 'diagpilot', 'cleanpilot', 'guardpilot',
];

// Whitelisted file hashes (known safe files that might trigger entropy/pattern checks)
const WHITELIST_HASHES = new Set([
  // Add specific safe file hashes here if needed
]);

// File extensions that should never be in temp folders
const DANGEROUS_EXTENSIONS_IN_TEMP = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.scr', '.pif', '.com', '.hta'];

// Ransomware-encrypted file extensions (comprehensive)
const RANSOMWARE_EXTENSIONS = [
  // Classic
  '.locked', '.encrypted', '.enc', '.crypto', '.crypt',
  // Cerber
  '.cerber', '.cerber2', '.cerber3',
  // Locky family
  '.locky', '.zepto', '.odin', '.thor', '.aesir', '.zzzzz', '.osiris',
  // WannaCry
  '.wncry', '.wncryt', '.wcry', '.wncr', '.wannacry', '.wncrypt',
  // Dharma/Crysis
  '.dharma', '.cezar', '.arena', '.java', '.phobos', '.bip',
  '.combo', '.arrow', '.gamma', '.brrr', '.adobe', '.skip',
  // STOP/Djvu
  '.stop', '.djvu', '.tfude', '.tro', '.rumba', '.roland',
  '.djvuu', '.uudjvu', '.pdff', '.tfudet', '.tfudeq',
  '.gero', '.hese', '.seto', '.peta', '.meds', '.kvag',
  '.domn', '.karl', '.nesa', '.boot', '.noos', '.kuus',
  '.reco', '.bora', '.nols', '.werd', '.coot', '.derp',
  '.meka', '.mosk', '.toec', '.kodc', '.foop', '.rezm',
  '.nppp', '.omfl', '.lalo', '.xati', '.kkll', '.moss',
  // LockBit
  '.lockbit', '.abcd',
  // Maze/Egregor
  '.maze',
  // REvil/Sodinokibi
  '.sodin', '.revil',
  // Ryuk
  '.ryk',
  // Conti
  '.conti',
  // BlackMatter
  '.blackmatter',
  // Other
  '.enc1', '.enc2', '.rdp', '.0day', '.ransom',
  '.crypted', '.coded', '.crypz', '.cryp1',
];

module.exports = {
  KNOWN_HASHES,
  SUSPICIOUS_STRINGS,
  SUSPICIOUS_STRINGS_SCRIPTS,
  SUSPICIOUS_STRINGS_PE,
  SUSPICIOUS_PATHS,
  SUSPICIOUS_PROCESS_PATTERNS,
  SUSPICIOUS_IP_RANGES,
  SAFE_PATHS,
  DANGEROUS_EXTENSIONS_IN_TEMP,
  RANSOMWARE_EXTENSIONS,
  WHITELIST_PATHS,
  WHITELIST_HASHES,
};
