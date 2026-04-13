'use strict';

const { workerData, parentPort } = require('worker_threads');
const scanner = require('./scanner');

const { scanType, folderPath } = workerData;

async function run() {
  const onProgress = (p) => parentPort.postMessage({ type: 'progress', data: p });
  let threats;
  if (scanType === 'quick') {
    threats = await scanner.quickScan(onProgress);
  } else if (scanType === 'full') {
    threats = await scanner.fullScan(onProgress);
  } else if (scanType === 'custom') {
    threats = await scanner.customScan(folderPath, onProgress);
  }
  parentPort.postMessage({ type: 'done', threats });
}

run().catch(e => parentPort.postMessage({ type: 'error', message: e.message }));
