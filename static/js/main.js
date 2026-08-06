// Console bootstrap: form wiring, module toggles, shortcuts, message routing.
import * as ws from './ws.js';
import {
  announce, canonicalTargetIdentity, createRequestID, fetchWithCSRF, readResponse, splitTargets, toast,
} from './util.js';
import {
  appendLog, beginScan, getCurrentScans, identityIsInFlight,
  readModuleConfig, enabledServiceCount, restoreActivity,
  applyPreset, saveSettings, loadSettings, updateModuleCount, moduleIds,
} from './store.js';
import {
  createCard, updateProgressBar, routeMessage, updateWorkspaceState,
  initDragOrdering, clearWorkspace, exportJSON, exportCSV, copyAllJSON,
  routeRequestEvent,
} from './cards.js';
import { initModal, openTool } from './history.js';

const MAX_TARGETS = 25;
const INPUT_KEY = 'whois_console_target_draft';
const NOTIFICATION_KEY = 'whois_scan_notifications';
let hadInFlightScans = false;

function persistInput(value) {
  try { window.localStorage.setItem(INPUT_KEY, value); } catch { /* storage unavailable */ }
}

function notifyCompletion(scans) {
  if (!hadInFlightScans || scans.some((scan) => ['queued', 'running'].includes(scan.status))) return;
  hadInFlightScans = false;
  let enabled = false;
  try { enabled = window.localStorage.getItem(NOTIFICATION_KEY) === 'true'; } catch { /* unavailable */ }
  if (!enabled || !('Notification' in window) || Notification.permission !== 'granted' || !document.hidden) return;
  const findings = scans.reduce((count, scan) => count + scan.failures.size + scan.findings.size, 0);
  new Notification('Network diagnostics complete', {
    body: `${scans.length} target${scans.length === 1 ? '' : 's'} finished${findings ? ` with ${findings} finding${findings === 1 ? '' : 's'}` : ''}.`,
    tag: 'whois-scan-complete',
  });
}

function syncScanLifecycle() {
  const scans = getCurrentScans();
  const queued = scans.filter((scan) => scan.status === 'queued').length;
  const active = scans.filter((scan) => scan.status === 'running').length;
  const inFlight = queued + active;
  const completedUnits = scans.reduce((sum, scan) => sum + Math.min(scan.completed || 0, scan.total || 0), 0);
  const totalUnits = scans.reduce((sum, scan) => sum + (scan.total || 0), 0);
  const percent = totalUnits > 0 ? Math.round((completedUnits / totalUnits) * 100) : 0;
  if (inFlight > 0) hadInFlightScans = true;

  let phase = 'READY';
  let detail = 'Awaiting an authorized target queue.';
  if (active > 0) {
    phase = 'RUNNING';
    detail = `${active} active target${active === 1 ? '' : 's'} streaming diagnostic results.`;
  } else if (queued > 0) {
    phase = 'QUEUED';
    detail = `${queued} target${queued === 1 ? '' : 's'} waiting for the diagnostic uplink.`;
  } else if (scans.length > 0) {
    const failed = scans.filter((scan) => ['failed', 'interrupted'].includes(scan.status)).length;
    phase = failed ? 'COMPLETE · REVIEW' : 'COMPLETE';
    detail = failed ? `${failed} target${failed === 1 ? '' : 's'} needs review; partial results remain exportable.` : 'All diagnostics completed. Results remain available for review and export.';
  }

  const setText = (id, value) => { const element = document.getElementById(id); if (element) element.textContent = value; };
  setText('scanPhaseLabel', phase);
  setText('scanPhaseDetail', detail);
  setText('queuedCount', String(queued));
  setText('activeCount', String(active));
  setText('totalProgressText', `${percent}%`);
  const progress = document.getElementById('totalProgress');
  if (progress) valueProgress(progress, percent);
  const cancel = document.getElementById('cancelAllBtn');
  if (cancel) cancel.disabled = inFlight === 0;
  const run = document.getElementById('runBtn');
  if (run) {
    run.classList.toggle('is-running', inFlight > 0);
    run.setAttribute('aria-busy', String(inFlight > 0));
    run.querySelector('span').textContent = inFlight > 0 ? `RUNNING · ${inFlight}` : 'RUN DIAGNOSTICS';
  }
  document.getElementById('resultsGrid')?.setAttribute('aria-busy', String(inFlight > 0));

  const mobile = document.getElementById('mobileScanStatus');
  if (mobile) mobile.hidden = scans.length === 0;
  setText('mobileScanPhase', phase);
  setText('mobileScanCounts', `${active} active · ${queued} queued`);
  const mobileProgress = document.getElementById('mobileScanProgress');
  if (mobileProgress) valueProgress(mobileProgress, percent);
  notifyCompletion(scans);
}

function valueProgress(progress, value) {
  progress.value = value;
  progress.textContent = `${value}%`;
  progress.setAttribute('aria-valuetext', `${value} percent complete`);
}

function startQuery() {
  const input = document.getElementById('targetInput');
  const error = document.getElementById('targetError');
  const targets = splitTargets(input.value);
  if (targets.length === 0) {
    error.textContent = 'Enter at least one domain, IP address, CIDR, ASN, or URL.';
    input.setAttribute('aria-invalid', 'true');
    input.focus();
    return;
  }
  if (targets.length > MAX_TARGETS) {
    error.textContent = `Enter no more than ${MAX_TARGETS} targets at a time.`;
    input.setAttribute('aria-invalid', 'true');
    input.focus();
    return;
  }
  const config = readModuleConfig();
  const total = enabledServiceCount(config);
  if (total === 0) {
    error.textContent = 'Select at least one diagnostic module.';
    announce(error.textContent);
    return;
  }
  const runnable = [];
  let duplicateCount = 0;
  targets.forEach((target) => {
    const identity = canonicalTargetIdentity(target);
    if (identityIsInFlight(identity)) duplicateCount += 1;
    else runnable.push({ target, identity });
  });
  if (runnable.length === 0) {
    error.textContent = 'Every target in this queue already has a diagnostic run in progress.';
    announce(error.textContent);
    return;
  }
  error.textContent = duplicateCount > 0
    ? `${duplicateCount} target${duplicateCount === 1 ? ' was' : 's were'} skipped because a run is already in progress.`
    : '';
  input.removeAttribute('aria-invalid');
  announce(`Starting diagnostics for ${runnable.length} ${runnable.length === 1 ? 'target' : 'targets'}.`);

  runnable.forEach(({ target, identity }) => {
    const requestID = createRequestID();
    beginScan(target, {
      requestID, identity, config, total,
    });
    createCard(target);
    updateProgressBar(target);
    appendLog(target, 'Initializing diagnostic vectors...');
    ws.send({ request_id: requestID, targets: [target], config });
  });
  persistInput(input.value);
  syncScanLifecycle();
}

function initForm() {
  const input = document.getElementById('targetInput');
  try { input.value = window.localStorage.getItem(INPUT_KEY) || input.value; } catch { /* unavailable */ }
  document.getElementById('queryForm').addEventListener('submit', (event) => {
    event.preventDefault();
    startQuery();
  });
  input.addEventListener('input', (event) => {
    event.target.removeAttribute('aria-invalid');
    document.getElementById('targetError').textContent = '';
    persistInput(event.target.value);
  });
}

function initModules() {
  loadSettings();
  updateModuleCount();
  moduleIds().forEach((id) => {
    const box = document.getElementById(`cfg-${id}`);
    if (box) {
      box.addEventListener('change', () => {
        saveSettings();
        updateModuleCount();
      });
    }
  });
  document.querySelectorAll('[data-module-preset]').forEach((button) => {
    button.addEventListener('click', () => applyPreset(button.dataset.modulePreset));
  });
  const portscanBox = document.getElementById('cfg-portscan');
  const portsField = document.getElementById('portsField');
  const syncPorts = () => portsField.classList.toggle('is-open', portscanBox.checked);
  portscanBox.addEventListener('change', syncPorts);
  document.addEventListener('console:modules-changed', syncPorts);
  document.getElementById('cfg-ports')?.addEventListener('input', saveSettings);
  syncPorts();
}

function initToolbar() {
  document.getElementById('copyJsonBtn').addEventListener('click', copyAllJSON);
  document.getElementById('exportJsonBtn').addEventListener('click', exportJSON);
  document.getElementById('exportCsvBtn').addEventListener('click', exportCSV);
  document.getElementById('clearBtn').addEventListener('click', () => {
    getCurrentScans().forEach((scan) => {
      if (scan.status === 'queued') ws.cancelQueued(scan.requestID);
    });
    clearWorkspace();
    const input = document.getElementById('targetInput');
    input.value = '';
    persistInput('');
    input.removeAttribute('aria-invalid');
    document.getElementById('targetError').textContent = '';
    updateWorkspaceState();
    announce('Workspace cleared.');
    input.focus();
  });
  document.getElementById('cancelAllBtn')?.addEventListener('click', () => {
    if (!ws.cancelAll()) return;
    announce('All queued and active diagnostics were canceled. Partial results remain available.');
  });
  document.querySelectorAll('[data-tool]').forEach((button) => {
    button.addEventListener('click', () => openTool(button.dataset.tool));
  });
  const bulkBtn = document.getElementById('bulkUploadBtn');
  const bulkInput = document.getElementById('bulkFileInput');
  if (bulkBtn && bulkInput) {
    bulkBtn.addEventListener('click', () => bulkInput.click());
    bulkInput.addEventListener('change', async () => {
      if (!bulkInput.files || bulkInput.files.length === 0) return;
      const form = new FormData();
      form.append('file', bulkInput.files[0]);
      try {
        const resp = await fetchWithCSRF('/bulk-upload', { method: 'POST', body: form });
        const data = await readResponse(resp, { json: true });
        const uploaded = Array.isArray(data.targets) ? splitTargets(data.targets.join('\n')) : [];
        if (uploaded.length === 0) throw new Error(data.error || 'No valid targets were found in that file.');
        const input = document.getElementById('targetInput');
        const combined = splitTargets(`${input.value}\n${uploaded.join('\n')}`);
        if (combined.length > MAX_TARGETS) {
          throw new Error(`The combined queue would exceed the ${MAX_TARGETS}-target limit.`);
        }
        input.value = combined.join(', ');
        input.removeAttribute('aria-invalid');
        document.getElementById('targetError').textContent = '';
        input.focus();
        announce(`${uploaded.length} unique target${uploaded.length === 1 ? '' : 's'} loaded; ${combined.length} in the queue.`);
      } catch (err) {
        const message = `Bulk upload failed: ${err.message || err}`;
        document.getElementById('targetError').textContent = message;
        announce(message);
      } finally {
        bulkInput.value = '';
      }
    });
  }
}

function initShortcuts() {
  document.addEventListener('keydown', (event) => {
    // Dialogs own the keyboard while open. In particular, do not allow the
    // global run shortcut to bypass the mandatory authorization disclosure.
    if (document.querySelector('.modal-backdrop.is-open')) return;
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      startQuery();
      return;
    }
    if (event.key === '/' && !/^(INPUT|TEXTAREA)$/.test(document.activeElement?.tagName || '')) {
      event.preventDefault();
      document.getElementById('targetInput').focus();
    }
  });
}

function initRescanBridge() {
  window.addEventListener('console:rescan', (event) => {
    const { target, config, request_id: requestID } = event.detail;
    ws.send({ request_id: requestID, targets: [target], config });
  });
  window.addEventListener('console:cancel-request', (event) => {
    ws.cancelQueued(event.detail?.request_id);
  });
  window.addEventListener('console:query-target', (event) => {
    const target = String(event.detail?.target || '').trim();
    if (!target) return;
    const input = document.getElementById('targetInput');
    input.value = target;
    persistInput(target);
    input.focus();
    startQuery();
  });
}

function init() {
  initForm();
  initModules();
  initToolbar();
  initShortcuts();
  initDragOrdering();
  initModal();
  initRescanBridge();
  document.addEventListener('console:scan-state', syncScanLifecycle);
  restoreActivity();
  ws.onMessage(routeMessage);
  ws.onTransportLog((message) => appendLog('SYSTEM', message));
  ws.onRequestEvent(routeRequestEvent);
  ws.connect();
  updateWorkspaceState();
  syncScanLifecycle();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

export { toast };
