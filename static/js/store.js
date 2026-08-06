// Console state: cards, scan progress, collected results, live log.
import { escapeHTML, timeStamp, targetColor, resetColors } from './util.js';

const activeScans = new Map();       // target -> { total, completed, failures:Set, findings:Set }
const diagnosticResults = new Map(); // target -> { service: data }
const pingCharts = new Map();        // canvas id -> chart
const ignoredTargets = new Set();

export function getScan(target) { return activeScans.get(target); }
export function setScan(target, scan) { activeScans.set(target, scan); }
export function dropScan(target) { activeScans.delete(target); }

export function getResults(target) {
  if (!diagnosticResults.has(target)) diagnosticResults.set(target, {});
  return diagnosticResults.get(target);
}

export function getAllResultsData() {
  const results = [];
  document.querySelectorAll('.result-card').forEach((card) => {
    const target = card.getAttribute('data-target');
    results.push({ target, services: diagnosticResults.get(target) || {} });
  });
  return results;
}

export function getCard(target) {
  return [...document.querySelectorAll('.result-card')]
    .find((card) => card.dataset.target === String(target)) || null;
}

export function registerChart(id, chart) { pingCharts.set(id, chart); }

export function destroyCharts(container) {
  container.querySelectorAll('canvas[id]').forEach((canvas) => {
    const chart = pingCharts.get(canvas.id);
    if (chart) chart.destroy();
    pingCharts.delete(canvas.id);
  });
}

export function ignoreTarget(target) { ignoredTargets.add(target); }
export function unignoreTarget(target) { ignoredTargets.delete(target); }

export function removeCard(target) {
  const card = getCard(target);
  if (!card) return;
  ignoredTargets.add(target);
  destroyCharts(card);
  card.remove();
  activeScans.delete(target);
  diagnosticResults.delete(target);
}

export function clearWorkspace() {
  document.querySelectorAll('.result-card').forEach((card) => ignoredTargets.add(card.dataset.target));
  pingCharts.forEach((chart) => chart.destroy());
  pingCharts.clear();
  document.getElementById('resultsGrid').innerHTML = '';
  activeScans.clear();
  diagnosticResults.clear();
  resetColors();
}

export function cardCount() {
  return document.querySelectorAll('.result-card').length;
}

/* ---------- live log ---------- */

export function appendLog(target, message) {
  const log = document.getElementById('liveLog');
  if (!log) return;
  const entry = document.createElement('div');
  const color = targetColor(target);
  entry.innerHTML =
    `<span class="log-time">[${timeStamp()}]</span> ` +
    `<span class="log-target" style="color:${color}">${escapeHTML(target)}</span> ` +
    `<span>▸ ${escapeHTML(message)}</span>`;
  const empty = log.querySelector('.live-log__empty');
  if (empty) empty.remove();
  log.appendChild(entry);
  while (log.children.length > 400) log.removeChild(log.firstChild);
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
    config[id] = Boolean(box && box.checked);
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
    if (box) box.checked = enabled.includes(id);
  });
  saveSettings();
  updateModuleCount();
}

export function saveSettings() {
  try {
    const state = {};
    MODULE_IDS.forEach((id) => {
      const box = document.getElementById(`cfg-${id}`);
      state[id] = Boolean(box && box.checked);
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
    if (box && typeof state[id] === 'boolean') box.checked = state[id];
  });
  const ports = document.getElementById('cfg-ports');
  if (ports && typeof state.portsValue === 'string') ports.value = state.portsValue;
}

export function updateModuleCount() {
  const el = document.getElementById('activeModuleCount');
  if (!el) return;
  const config = readModuleConfig();
  el.textContent = `${enabledServiceCount(config)} / ${MODULE_IDS.length}`;
}

export function moduleIds() { return MODULE_IDS.slice(); }
