// Console bootstrap: form wiring, module toggles, shortcuts, message routing.
import * as ws from './ws.js';
import { announce, toast } from './util.js';
import {
  appendLog, readModuleConfig, enabledServiceCount, setScan,
  applyPreset, saveSettings, loadSettings, updateModuleCount, moduleIds,
} from './store.js';
import {
  createCard, updateProgressBar, routeMessage, updateWorkspaceState,
  initDragOrdering, clearWorkspace, exportJSON, exportCSV, copyAllJSON,
} from './cards.js';
import { initModal, openTool } from './history.js';

const MAX_TARGETS = 25;

function startQuery() {
  const input = document.getElementById('targetInput');
  const error = document.getElementById('targetError');
  const targets = [...new Set(input.value.split(',').map((t) => t.trim()).filter(Boolean))];
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
  error.textContent = '';
  input.removeAttribute('aria-invalid');
  announce(`Starting diagnostics for ${targets.length} ${targets.length === 1 ? 'target' : 'targets'}.`);

  const runBtn = document.getElementById('runBtn');
  runBtn.classList.add('is-running');
  window.setTimeout(() => runBtn.classList.remove('is-running'), 1200);

  targets.forEach((target) => {
    createCard(target);
    setScan(target, { total, completed: 0, failures: new Set(), findings: new Set() });
    updateProgressBar(target);
    appendLog(target, 'Initializing diagnostic vectors...');
    ws.send({ targets: [target], config });
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
  syncPorts();
}

function initToolbar() {
  document.getElementById('copyJsonBtn').addEventListener('click', copyAllJSON);
  document.getElementById('exportJsonBtn').addEventListener('click', exportJSON);
  document.getElementById('exportCsvBtn').addEventListener('click', exportCSV);
  document.getElementById('clearBtn').addEventListener('click', () => {
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
        const resp = await fetch('/bulk-upload', { method: 'POST', body: form });
        const data = await resp.json();
        if (!resp.ok || data.error) {
          announce(`Bulk upload failed: ${data.error || resp.status}`);
          return;
        }
        const input = document.getElementById('targetInput');
        const existing = input.value.trim();
        input.value = (existing ? `${existing}, ` : '') + data.targets.join(', ');
        input.focus();
        announce(`${data.count} targets loaded into the queue.`);
      } catch (err) {
        announce(`Bulk upload failed: ${err.message}`);
      } finally {
        bulkInput.value = '';
      }
    });
  }
}

function initShortcuts() {
  document.addEventListener('keydown', (event) => {
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
    const { target, config } = event.detail;
    ws.send({ targets: [target], config });
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
  ws.onMessage(routeMessage);
  ws.onTransportLog((message) => appendLog('SYSTEM', message));
  ws.connect();
  updateWorkspaceState();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

export { toast };
