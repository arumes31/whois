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

  const runBtn = document.getElementById('runBtn');
  runBtn.classList.add('is-running');
  window.setTimeout(() => runBtn.classList.remove('is-running'), 1200);

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
}

function initForm() {
  document.getElementById('queryForm').addEventListener('submit', (event) => {
    event.preventDefault();
    startQuery();
  });
  document.getElementById('targetInput').addEventListener('input', (event) => {
    event.target.removeAttribute('aria-invalid');
    document.getElementById('targetError').textContent = '';
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
    input.removeAttribute('aria-invalid');
    document.getElementById('targetError').textContent = '';
    updateWorkspaceState();
    announce('Workspace cleared.');
    input.focus();
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
}

function init() {
  initForm();
  initModules();
  initToolbar();
  initShortcuts();
  initDragOrdering();
  initModal();
  initRescanBridge();
  restoreActivity();
  ws.onMessage(routeMessage);
  ws.onTransportLog((message) => appendLog('SYSTEM', message));
  ws.onRequestEvent(routeRequestEvent);
  ws.connect();
  updateWorkspaceState();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

export { toast };
