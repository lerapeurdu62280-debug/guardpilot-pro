'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('gp', {
  winMin:   () => ipcRenderer.send('win-min'),
  winMax:   () => ipcRenderer.send('win-max'),
  winClose: () => ipcRenderer.send('win-close'),

  checkLicense:     ()  => ipcRenderer.invoke('check-license'),
  activateLicense:  (k) => ipcRenderer.invoke('activate-license', k),
  deactivateLicense:()  => ipcRenderer.invoke('deactivate-license'),

  quickScan:        ()      => ipcRenderer.invoke('quick-scan'),
  fullScan:         ()      => ipcRenderer.invoke('full-scan'),
  customScan:       (p)     => ipcRenderer.invoke('custom-scan', p),
  chooseScanFolder: ()      => ipcRenderer.invoke('choose-scan-folder'),

  auditRegistry:    ()      => ipcRenderer.invoke('audit-registry'),
  auditProcesses:   ()      => ipcRenderer.invoke('audit-processes'),
  auditNetwork:     ()      => ipcRenderer.invoke('audit-network'),
  auditVulnerabilities: ()  => ipcRenderer.invoke('audit-vulnerabilities'),
  getDefenderStatus:()      => ipcRenderer.invoke('get-defender-status'),
  updateDefenderSigs:()     => ipcRenderer.invoke('update-defender-signatures'),
  updateGuardPilotSigs: ()  => ipcRenderer.invoke('update-guardpilot-signatures'),
  getSignaturesInfo:    ()  => ipcRenderer.invoke('get-signatures-info'),
  getDefenderThreats:()     => ipcRenderer.invoke('get-defender-threats'),

  quarantineFile:   (p)     => ipcRenderer.invoke('quarantine-file', p),
  getQuarantine:    ()      => ipcRenderer.invoke('get-quarantine'),
  restoreQuarantine:(opts)  => ipcRenderer.invoke('restore-quarantine', opts),
  deleteQuarantine: (p)     => ipcRenderer.invoke('delete-quarantine', p),

  auditTasks:       ()      => ipcRenderer.invoke('audit-tasks'),
  auditServices:    ()      => ipcRenderer.invoke('audit-services'),
  auditWMI:         ()      => ipcRenderer.invoke('audit-wmi'),
  auditHosts:       ()      => ipcRenderer.invoke('audit-hosts'),
  auditIFEO:        ()      => ipcRenderer.invoke('audit-ifeo'),
  auditAppInit:     ()      => ipcRenderer.invoke('audit-appinit'),
  auditExtensions:  ()      => ipcRenderer.invoke('audit-extensions'),
  auditShadows:     ()      => ipcRenderer.invoke('audit-shadows'),
  auditAdvanced:    ()      => ipcRenderer.invoke('audit-advanced'),
  deletePublicMalware: (p)  => ipcRenderer.invoke('delete-public-malware', p),
  removeScheduledTask:(opts)=> ipcRenderer.invoke('remove-scheduled-task', opts),
  removeWMISubscription:(o) => ipcRenderer.invoke('remove-wmi-subscription', o),

  removeAutorun:    (opts)  => ipcRenderer.invoke('remove-autorun', opts),
  killProcess:      (pid)   => ipcRenderer.invoke('kill-process', pid),

  startRealtime:    ()      => ipcRenderer.invoke('start-realtime'),
  stopRealtime:     ()      => ipcRenderer.invoke('stop-realtime'),
  getRealtimeStatus:()      => ipcRenderer.invoke('get-realtime-status'),

  getScanHistory:   ()      => ipcRenderer.invoke('get-scan-history'),
  getLastScan:      ()      => ipcRenderer.invoke('get-last-scan'),
  getStats:         ()      => ipcRenderer.invoke('get-stats'),
  clearHistory:     ()      => ipcRenderer.invoke('clear-history'),
  exportPDF:        (data)  => ipcRenderer.invoke('export-pdf', data),
  exportWord:       (data)  => ipcRenderer.invoke('export-word', data),

  deleteFile:       (p)     => ipcRenderer.invoke('delete-file', p),
  analyzeFile:      (p)     => ipcRenderer.invoke('analyze-file', p),

  logAction:        (a)     => ipcRenderer.invoke('log-action', a),
  getActionLog:     ()      => ipcRenderer.invoke('get-action-log'),
  clearActionLog:   ()      => ipcRenderer.invoke('clear-action-log'),

  getExclusions:    ()      => ipcRenderer.invoke('get-exclusions'),
  addExclusion:     (p)     => ipcRenderer.invoke('add-exclusion', p),
  removeExclusion:  (p)     => ipcRenderer.invoke('remove-exclusion', p),
  chooseExclusionPath: ()   => ipcRenderer.invoke('choose-exclusion-path'),

  getPrefs:         ()      => ipcRenderer.invoke('get-prefs'),
  setPref:          (k,v)   => ipcRenderer.invoke('set-pref', { key:k, value:v }),

  getScheduledScans:()      => ipcRenderer.invoke('get-scheduled-scans'),
  scheduleScan:     (opts)  => ipcRenderer.invoke('schedule-scan', opts),
  unscheduleScan:   (name)  => ipcRenderer.invoke('unschedule-scan', name),

  openRepairPilot:  (data)  => ipcRenderer.invoke('open-repairpilot', data),

  onScanProgress:   (cb)    => ipcRenderer.on('scan-progress', (_, d) => cb(d)),
  onRealtimeThreat: (cb)    => ipcRenderer.on('realtime-threat', (_, d) => cb(d)),
  onRealtimeActivity:(cb)   => ipcRenderer.on('realtime-activity', (_, d) => cb(d)),
  removeAllListeners:(ch)   => ipcRenderer.removeAllListeners(ch),
});
