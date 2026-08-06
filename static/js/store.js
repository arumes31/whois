// Console state: cards, scan progress, collected results, live log.
import { timeStamp, targetColor, resetColors } from './util.js';

const activeScans = new Map();       // target -> current scan generation (terminal generations retained for export)
const requestTargets = new Map();    // request id -> target for current generations
const activeIdentityRequests = new Map(); // canonical identity -> queued/running request id
const diagnosticResults = new Map(); // target -> { service: data }
const pingCharts = new Map();        // canvas id -> chart

const TERMINAL_SCAN_STATES = new Set(['completed', 'failed', 'interrupted']);

export function getScan(target) { return activeScans.get(target); }

export function getScanByRequestID(requestID) {
  const id = String(requestID || '');
  const target = requestTargets.get(id);
  if (!target) return null;
  const scan = activeScans.get(target);
  return scan?.requestID === id ? scan : null;
}

function detachScan(scan) {
  if (!scan) return;
  if (scan.requestID) requestTargets.delete(scan.requestID);
  if (scan.identity && activeIdentityRequests.get(scan.identity) === scan.requestID) {
    activeIdentityRequests.delete(scan.identity);
  }
}

export function setScan(target, scan) {
  detachScan(activeScans.get(target));
  const next = { target, ...scan };
  activeScans.set(target, next);
  if (next.requestID) requestTargets.set(next.requestID, target);
  if (next.identity && !TERMINAL_SCAN_STATES.has(next.status)) {
    activeIdentityRequests.set(next.identity, next.requestID);
  }
  return next;
}

export function beginScan(target, {
  requestID, identity, config, total,
}) {
  resetResults(target);
  return setScan(target, {
    requestID,
    identity,
    config: { ...config },
    total,
    completed: 0,
    completedServices: new Set(),
    failures: new Set(),
    findings: new Set(),
    status: 'queued',
    outcome: '',
    startedAt: new Date().toISOString(),
    completedAt: '',
    targetProfile: null,
  });
}

export function setScanStatusByRequestID(requestID, status, outcome = '') {
  const scan = getScanByRequestID(requestID);
  if (!scan) return null;
  scan.status = status;
  if (outcome) scan.outcome = outcome;
  if (TERMINAL_SCAN_STATES.has(status)) {
    scan.completedAt = new Date().toISOString();
    if (scan.identity && activeIdentityRequests.get(scan.identity) === scan.requestID) {
      activeIdentityRequests.delete(scan.identity);
    }
  }
  return scan;
}

export function identityIsInFlight(identity) {
  return activeIdentityRequests.has(identity);
}

export function getCurrentScans() {
  return [...activeScans.values()];
}

export function dropScan(target) {
  detachScan(activeScans.get(target));
  activeScans.delete(target);
}

export function getResults(target) {
  if (!diagnosticResults.has(target)) diagnosticResults.set(target, {});
  return diagnosticResults.get(target);
}

export function resetResults(target) {
  diagnosticResults.set(target, {});
}

export function getAllResultsData() {
  const results = [];
  document.querySelectorAll('.result-card').forEach((card) => {
    const target = card.getAttribute('data-target');
    const services = diagnosticResults.get(target) || {};
    const scan = activeScans.get(target);
    const serviceCount = Object.keys(services).length;
    const status = scan?.status || 'completed';
    const completed = scan?.completed ?? scan?.completedServices?.size ?? 0;
    const total = scan?.total || 0;
    results.push({
      target,
      request_id: scan?.requestID || '',
      status,
      outcome: scan?.outcome || '',
      partial: status !== 'completed' && serviceCount > 0,
      started_at: scan?.startedAt || '',
      completed_at: scan?.completedAt || '',
      progress: {
        completed,
        total,
        percent: total > 0 ? Math.min(100, Math.round((completed / total) * 100)) : 0,
      },
      config: scan?.config ? { ...scan.config } : {},
      services,
    });
  });
  return results;
}

export function hasExportableResults() {
  return [...diagnosticResults.values()].some((services) => Object.keys(services).length > 0);
}

export function getCard(target) {
  return [...document.querySelectorAll('.result-card')]
    .find((card) => card.dataset.target === String(target)) || null;
}

export function registerChart(id, chart) { pingCharts.set(id, chart); }

export function destroySectionChart(section) {
  if (!section) return;
  const id = section.dataset.chartId;
  const registered = id ? pingCharts.get(id) : null;
  if (registered) {
    registered.destroy();
    pingCharts.delete(id);
  } else if (section._pingChart) {
    section._pingChart.destroy();
  }
  section._pingChart = undefined;
  delete section.dataset.chartId;
  delete section.dataset.chartRtts;
}

export function destroyCharts(container) {
  if (container.matches?.('.service-section')) destroySectionChart(container);
  container.querySelectorAll('.service-section').forEach(destroySectionChart);
  container.querySelectorAll('canvas[id]').forEach((canvas) => {
    const chart = pingCharts.get(canvas.id);
    if (chart) chart.destroy();
    pingCharts.delete(canvas.id);
  });
}

export function removeCard(target) {
  const card = getCard(target);
  if (!card) return;
  destroyCharts(card);
  card.remove();
  dropScan(target);
  diagnosticResults.delete(target);
}

export function clearWorkspace() {
  pingCharts.forEach((chart) => chart.destroy());
  pingCharts.clear();
  document.getElementById('resultsGrid').innerHTML = '';
  activeScans.clear();
  requestTargets.clear();
  activeIdentityRequests.clear();
  diagnosticResults.clear();
  resetColors();
}

export function cardCount() {
  return document.querySelectorAll('.result-card').length;
}

/* ---------- live log ---------- */

const ACTIVITY_KEY = 'whois_console_activity';
const MAX_ACTIVITY_ENTRIES = 400;
const MAX_ACTIVITY_TIME_LENGTH = 64;
const MAX_ACTIVITY_TARGET_LENGTH = 512;
const MAX_ACTIVITY_MESSAGE_LENGTH = 4096;
let activityEntries = [];

function normalizeActivityEntry(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  if (typeof value.time !== 'string' || typeof value.target !== 'string' || typeof value.message !== 'string') return null;
  const entry = {
    time: value.time.slice(0, MAX_ACTIVITY_TIME_LENGTH),
    target: value.target.slice(0, MAX_ACTIVITY_TARGET_LENGTH),
    message: value.message.slice(0, MAX_ACTIVITY_MESSAGE_LENGTH),
  };
  return entry.time && entry.target && entry.message ? entry : null;
}

function renderLogEntry(log, entryData) {
  const entry = document.createElement('div');
  const time = document.createElement('span');
  time.className = 'log-time';
  time.textContent = `[${entryData.time}]`;
  const target = document.createElement('span');
  target.className = 'log-target';
  target.style.color = targetColor(entryData.target);
  target.textContent = entryData.target;
  const message = document.createElement('span');
  message.className = 'log-message';
  message.textContent = `▸ ${entryData.message}`;
  entry.append(time, document.createTextNode(' '), target, document.createTextNode(' '), message);
  log.appendChild(entry);
}

function persistActivity() {
  try { window.sessionStorage.setItem(ACTIVITY_KEY, JSON.stringify(activityEntries)); } catch { /* storage unavailable */ }
}

export function restoreActivity() {
  const log = document.getElementById('liveLog');
  if (!log) return;
  let storageNeedsRepair = false;
  try {
    const stored = JSON.parse(window.sessionStorage.getItem(ACTIVITY_KEY) || '[]');
    if (Array.isArray(stored)) {
      const recent = stored.slice(-MAX_ACTIVITY_ENTRIES);
      activityEntries = recent.map(normalizeActivityEntry).filter(Boolean);
      storageNeedsRepair = activityEntries.length !== recent.length || stored.length > MAX_ACTIVITY_ENTRIES;
    } else {
      activityEntries = [];
      storageNeedsRepair = true;
    }
  } catch {
    activityEntries = [];
    storageNeedsRepair = true;
  }
  if (storageNeedsRepair) persistActivity();
  if (activityEntries.length === 0) return;

  // Populate persisted history without announcing hundreds of old entries as
  // new live events. Future socket messages resume the original live setting.
  const liveSetting = log.getAttribute('aria-live');
  log.setAttribute('aria-live', 'off');
  log.setAttribute('aria-busy', 'true');
  const fragment = document.createDocumentFragment();
  activityEntries.forEach((entry) => renderLogEntry(fragment, entry));
  log.replaceChildren(fragment);
  log.scrollTop = log.scrollHeight;
  window.requestAnimationFrame(() => {
    if (!log.isConnected) return;
    log.removeAttribute('aria-busy');
    window.requestAnimationFrame(() => {
      if (!log.isConnected) return;
      if (liveSetting === null) log.removeAttribute('aria-live');
      else log.setAttribute('aria-live', liveSetting);
    });
  });
}

export function appendLog(target, message) {
  const log = document.getElementById('liveLog');
  if (!log) return;
  const entryData = normalizeActivityEntry({ time: timeStamp(), target: String(target), message: String(message) });
  if (!entryData) return;
  const empty = log.querySelector('.live-log__empty');
  if (empty) empty.remove();
  activityEntries.push(entryData);
  activityEntries = activityEntries.slice(-MAX_ACTIVITY_ENTRIES);
  renderLogEntry(log, entryData);
  while (log.children.length > MAX_ACTIVITY_ENTRIES) log.removeChild(log.firstChild);
  persistActivity();
  log.scrollTop = log.scrollHeight;
}

/* ---------- module settings (persisted on device) ---------- */

const SETTINGS_KEY = 'whois_console_modules';
const MODULE_IDS = ['whois', 'dns', 'subdomains', 'ssl', 'http', 'geo', 'ct', 'ping', 'trace', 'route', 'portscan'];

const PRESETS = {
  standard: ['whois', 'dns', 'ssl', 'http', 'geo'],
  web: ['ssl', 'http', 'ct', 'geo'],
  dns: ['dns', 'trace', 'subdomains'],
  full: MODULE_IDS,
};

export function readModuleConfig() {
  const config = {};
  MODULE_IDS.forEach((id) => {
    const box = document.getElementById(`cfg-${id}`);
    config[id] = Boolean(box && !box.disabled && box.checked);
  });
  const portsBox = document.getElementById('cfg-ports');
  config.ports = config.portscan && portsBox ? portsBox.value : '';
  return config;
}

export function enabledServiceCount(config) {
  return Object.entries(config).filter(([key, value]) => key !== 'ports' && value).length;
}

export function applyPreset(name) {
  const enabled = PRESETS[name] || [];
  MODULE_IDS.forEach((id) => {
    const box = document.getElementById(`cfg-${id}`);
    if (box) box.checked = !box.disabled && enabled.includes(id);
  });
  saveSettings();
  updateModuleCount();
  document.dispatchEvent(new CustomEvent('console:modules-changed'));
}

export function saveSettings() {
  try {
    const state = {};
    MODULE_IDS.forEach((id) => {
      const box = document.getElementById(`cfg-${id}`);
      state[id] = Boolean(box && !box.disabled && box.checked);
    });
    const ports = document.getElementById('cfg-ports');
    if (ports) state.portsValue = ports.value;
    window.localStorage.setItem(SETTINGS_KEY, JSON.stringify(state));
  } catch { /* storage unavailable */ }
}

export function loadSettings() {
  let state = null;
  try {
    state = JSON.parse(window.localStorage.getItem(SETTINGS_KEY) || 'null');
  } catch { state = null; }
  if (!state) return;
  MODULE_IDS.forEach((id) => {
    const box = document.getElementById(`cfg-${id}`);
    if (box && typeof state[id] === 'boolean') box.checked = !box.disabled && state[id];
  });
  const ports = document.getElementById('cfg-ports');
  if (ports && typeof state.portsValue === 'string') ports.value = state.portsValue;
}

export function updateModuleCount() {
  const el = document.getElementById('activeModuleCount');
  if (!el) return;
  const config = readModuleConfig();
  el.textContent = `${enabledServiceCount(config)} / ${MODULE_IDS.length}`;
  syncPresetState(config);
}

function syncPresetState(config = readModuleConfig()) {
  const selected = MODULE_IDS.filter((id) => config[id]);
  document.querySelectorAll('[data-module-preset]').forEach((button) => {
    const expected = (PRESETS[button.dataset.modulePreset] || [])
      .filter((id) => !document.getElementById(`cfg-${id}`)?.disabled);
    const active = selected.length === expected.length
      && expected.every((id) => selected.includes(id));
    button.classList.toggle('is-active', active);
    button.setAttribute('aria-pressed', String(active));
  });
}

export function moduleIds() { return MODULE_IDS.slice(); }
