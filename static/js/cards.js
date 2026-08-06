// Result cards: creation, drag ordering, progress, message routing.
import {
  announce, copyText, wireCopyable, resultHasError, downloadBlob, escapeHTML,
  canonicalTargetIdentity, createRequestID, isPlainObject,
} from './util.js';
import {
  getScan, getScanByRequestID, beginScan, setScanStatusByRequestID,
  identityIsInFlight, getResults, getAllResultsData, getCard,
  registerChart, destroyCharts, destroySectionChart, removeCard, clearWorkspace, cardCount,
  appendLog, readModuleConfig, enabledServiceCount, hasExportableResults,
} from './store.js';
import { renderService, skeletonHtml, skippedDetails, serviceLabel } from './render.js';

const SERVICE_ORDER = ['target', 'geo', 'whois', 'dns', 'subdomains', 'portscan', 'ping', 'route', 'trace', 'ssl', 'http', 'ct'];

/* ---------- workspace chrome ---------- */

export function updateWorkspaceState() {
  const count = cardCount();
  const empty = document.getElementById('emptyResults');
  const summary = document.getElementById('resultsSummary');
  if (empty) empty.hidden = count > 0;
  if (summary) {
    summary.textContent = count === 0
      ? 'NO SCANS IN THIS WORKSPACE'
      : `${count} TARGET${count === 1 ? '' : 'S'} IN THIS WORKSPACE`;
  }
  document.querySelectorAll('[data-result-action]').forEach((button) => {
    button.disabled = !hasExportableResults();
  });
}

/* ---------- card construction ---------- */

export function createCard(target) {
  const existing = getCard(target);
  if (existing) {
    destroyCharts(existing);
    existing.remove();
  }
  getResults(target);

  const article = document.createElement('article');
  article.className = 'result-card';
  article.dataset.target = target;
  article.setAttribute('aria-busy', 'true');
  const titleId = `target-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  article.innerHTML = `
    <div class="result-card__head">
        <button type="button" class="result-card__handle" draggable="true" title="Drag to reorder; use arrow keys to move" aria-label="Reorder ${escapeHTML(target)}; use arrow keys to move">⣿⣿</button>
      <div class="result-card__id">
        <span class="result-card__eyebrow">TARGET / LIVE ANALYSIS</span>
        <h3 class="result-card__target" id="${titleId}">${escapeHTML(target)}</h3>
      </div>
      <div class="result-card__meta">
        <span class="badge finding-count" hidden>0 findings</span>
        <span class="badge badge--run status-badge">QUEUED</span>
        <button type="button" class="icon-btn" data-card-action="history" title="View scan history" aria-label="View scan history">
          <svg viewBox="0 0 512 512"><path d="M75 75L41 109c-9.4 9.4-9.4 24.6 0 33.9L190.1 292 41 441.1c-9.4 9.4-9.4 24.6 0 33.9l34 34c9.4 9.4 24.6 9.4 33.9 0L257.9 360l149.1 149.1c9.4 9.4 24.6 9.4 33.9 0l34-34c9.4-9.4 9.4-24.6 0-33.9L325.8 292l149-149.1c9.4-9.4 9.4-24.6 0-33.9l-34-34c-9.4-9.4-24.6-9.4-33.9 0L257.9 224 108.9 75c-9.4-9.4-24.6-9.4-33.9 0z" transform="scale(0)"/><path d="M256 0a256 256 0 1 1 0 512 256 256 0 1 1 0-512zm0 96c-13.3 0-24 10.7-24 24V256c0 6.4 2.5 12.5 7 17l72 72c9.4 9.4 24.6 9.4 33.9 0s9.4-24.6 0-33.9l-65-65V120c0-13.3-10.7-24-24-24z"/></svg>
        </button>
        <button type="button" class="icon-btn" data-card-action="rescan" title="Rescan target" aria-label="Rescan target">
          <svg viewBox="0 0 512 512"><path d="M105.1 202.6c7.7-21.8 20.2-42.3 37.8-59.8 62.5-62.5 163.8-62.5 226.3 0L386.3 160H336c-17.7 0-32 14.3-32 32s14.3 32 32 32H464c17.7 0 32-14.3 32-32V64c0-17.7-14.3-32-32-32s-32 14.3-32 32v51.2L414.4 97.6c-87.5-87.5-229.3-87.5-316.8 0C73.2 122 55.6 150.7 44.8 181.4c-5.9 16.7 2.9 34.9 19.5 40.8s34.9-2.9 40.8-19.5zM39 289.4c-7.7 21.8-20.2 42.3-37.8 59.8-62.5 62.5-163.8 62.5-226.3 0l-17.1-17.1H336c17.7 0 32 14.3 32 32s-14.3 32-32 32H336c-17.7 0-32 14.3-32 32v128c0 17.7 14.3 32 32 32s32-14.3 32-32V396.8l17.1 17.1c87.5 87.5 229.3 87.5 316.8 0c24.4-24.4 42.1-53.1 52.9-83.7 5.9-16.7 2.9-34.9-19.5-40.8s-34.9-2.9-40.8 19.5z"/></svg>
        </button>
        <button type="button" class="icon-btn" data-card-action="copy" title="Copy full report" aria-label="Copy full report">
          <svg viewBox="0 0 448 512"><path d="M208 0H332.1c12.7 0 24.9 5.1 33.9 14.1l67.9 67.9c9 9 14.1 21.2 14.1 33.9V336c0 26.5-21.5 48-48 48H208c-26.5 0-48-21.5-48-48V48c0-26.5 21.5-48 48-48zM48 128h80v64H64V448H192V336c0-26.5 21.5-48 48-48h80V128H48z"/></svg>
        </button>
        <button type="button" class="icon-btn" data-card-action="close" title="Close widget" aria-label="Close widget">
          <svg viewBox="0 0 384 512"><path d="M342.6 150.6c12.5 12.5 12.5 32.8 0 45.3L192 210.7 86.6 105.4c-12.5-12.5-12.5-32.8 0-45.3s32.8-12.5 45.3 0L146.7 256 41.4 361.4c-12.5 12.5-12.5 32.8 0 45.3s12.5 32.8 0 45.3L192 301.3 297.4 406.6c12.5 12.5 32.8 12.5 45.3 0s12.5-32.8 0-45.3L237.3 256 342.6 150.6z"/></svg>
        </button>
      </div>
    </div>
    <div class="result-card__progress" role="progressbar" aria-label="Diagnostic progress for ${escapeHTML(target)}" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" aria-valuetext="Starting diagnostics"><i></i></div>
    <div class="result-card__body diagnostic-content">
      ${SERVICE_ORDER.map((s) => `<div class="service-section" data-service="${s}"></div>`).join('')}
    </div>`;

  article.setAttribute('aria-labelledby', titleId);
  article.tabIndex = -1;

  // seed skeletons for enabled modules
  const config = getScan(target)?.config || readModuleConfig();
  Object.entries(config).forEach(([service, enabled]) => {
    if (!enabled) return;
    const section = article.querySelector(`[data-service="${service}"]`);
    if (section) section.innerHTML = skeletonHtml();
  });

  // card actions
  article.querySelector('[data-card-action="close"]').addEventListener('click', () => {
    const cards = [...document.querySelectorAll('.result-card')];
    const index = cards.indexOf(article);
    const focusTarget = cards[index + 1] || cards[index - 1]
      || document.getElementById('resultsHeading') || document.getElementById('targetInput');
    const requestID = getScan(target)?.requestID;
    if (requestID) {
      window.dispatchEvent(new CustomEvent('console:cancel-request', { detail: { request_id: requestID } }));
    }
    removeCard(target);
    updateWorkspaceState();
    announce(`${target} removed from the workspace.`);
    focusTarget?.focus();
  });
  article.querySelector('[data-card-action="rescan"]').addEventListener('click', () => {
    const runConfig = readModuleConfig();
    const total = enabledServiceCount(runConfig);
    if (total === 0) {
      announce('Select at least one diagnostic module before rescanning.');
      document.querySelector('.module-toggle input:not(:disabled)')?.focus();
      return;
    }
    const identity = canonicalTargetIdentity(target);
    if (identityIsInFlight(identity)) {
      announce(`${target} already has a diagnostic run in progress.`);
      return;
    }
    const requestID = createRequestID();
    beginScan(target, {
      requestID, identity, config: runConfig, total,
    });
    createCard(target);
    updateProgressBar(target);
    getCard(target)?.focus();
    window.dispatchEvent(new CustomEvent('console:rescan', {
      detail: { target, config: runConfig, request_id: requestID },
    }));
  });
  article.querySelector('[data-card-action="copy"]').addEventListener('click', (event) => {
    copyTargetReport(article);
    event.currentTarget.style.borderColor = 'var(--phos)';
  });
  article.querySelector('[data-card-action="history"]').addEventListener('click', () => {
    window.dispatchEvent(new CustomEvent('console:history', { detail: { target } }));
  });

  // drag to reorder
  const handle = article.querySelector('.result-card__handle');
  handle.addEventListener('dragstart', (event) => {
    article.classList.add('dragging');
    event.dataTransfer.setData('text/plain', target);
  });
  handle.addEventListener('dragend', () => article.classList.remove('dragging'));
  handle.addEventListener('keydown', (event) => {
    const backward = event.key === 'ArrowUp' || event.key === 'ArrowLeft';
    const forward = event.key === 'ArrowDown' || event.key === 'ArrowRight';
    if (!backward && !forward) return;
    const sibling = backward ? article.previousElementSibling : article.nextElementSibling;
    if (!sibling?.classList.contains('result-card')) return;
    event.preventDefault();
    if (backward) article.parentElement.insertBefore(article, sibling);
    else article.parentElement.insertBefore(sibling, article);
    const position = [...article.parentElement.querySelectorAll('.result-card')].indexOf(article) + 1;
    announce(`${target} moved to position ${position}.`);
    handle.focus();
  });

  document.getElementById('resultsGrid').appendChild(article);
  syncCardStatus(target);
  updateWorkspaceState();
}

export function initDragOrdering() {
  const grid = document.getElementById('resultsGrid');
  grid.addEventListener('dragover', (event) => {
    event.preventDefault();
    const dragging = grid.querySelector('.dragging');
    if (!dragging) return;
    const after = getDragAfterElement(grid, event.clientX, event.clientY);
    if (after == null) grid.appendChild(dragging);
    else grid.insertBefore(dragging, after);
  });
}

function getDragAfterElement(container, x, y) {
  const elements = [...container.querySelectorAll('.result-card:not(.dragging)')];
  return elements.reduce((closest, child) => {
    const box = child.getBoundingClientRect();
    const dx = x - box.left - box.width / 2;
    const dy = y - box.top - box.height / 2;
    const distance = Math.sqrt(dx * dx + dy * dy);
    return distance < closest.distance ? { distance, element: child } : closest;
  }, { distance: Number.POSITIVE_INFINITY }).element;
}

/* ---------- progress ---------- */

const STATUS_PRESENTATION = {
  queued: { label: 'QUEUED', badge: 'badge--run', busy: true, progress: 'Queued until the uplink is available' },
  running: { label: 'RUNNING', badge: 'badge--run', busy: true, progress: null },
  failed: { label: 'FAILED', badge: 'badge--err', busy: false, progress: 'Diagnostics failed' },
  interrupted: { label: 'INTERRUPTED', badge: 'badge--warn', busy: false, progress: 'Diagnostics interrupted; partial results may be available' },
};

function syncCardStatus(target) {
  const card = getCard(target);
  const scan = getScan(target);
  if (!card || !scan) return;
  card.dataset.requestId = scan.requestID;
  card.dataset.scanStatus = scan.status;
  const presentation = STATUS_PRESENTATION[scan.status];
  if (presentation) {
    const badge = card.querySelector('.status-badge');
    badge.textContent = presentation.label;
    badge.className = `badge status-badge ${presentation.badge}`;
    card.setAttribute('aria-busy', String(presentation.busy));
    if (presentation.progress) {
      card.querySelector('.result-card__progress')?.setAttribute('aria-valuetext', presentation.progress);
    }
  }
  const inFlight = scan.status === 'queued' || scan.status === 'running';
  const rescan = card.querySelector('[data-card-action="rescan"]');
  if (rescan) rescan.disabled = inFlight;
}

function finishWithTransportFailure(scan, status, message, explicitOutcome = '') {
  const outcome = explicitOutcome
    || (status === 'interrupted' ? 'transport_interrupted' : 'request_rejected');
  setScanStatusByRequestID(scan.requestID, status, outcome);
  const card = getCard(scan.target);
  if (!card) return;
  card.querySelectorAll('.service-section').forEach((section) => {
    if (section.querySelector('.skel')) section.innerHTML = skippedDetails(section.dataset.service, status);
  });
  syncCardStatus(scan.target);
  appendLog(scan.target, message);
  announce(`${scan.target}: ${message}`);
  updateWorkspaceState();
}

export function routeRequestEvent(event) {
  const scan = getScanByRequestID(event.request_id);
  if (!scan) return;
  if (event.type === 'queued') {
    scan.status = 'queued';
    syncCardStatus(scan.target);
  } else if (event.type === 'sent') {
    scan.status = 'running';
    syncCardStatus(scan.target);
  } else if (event.type === 'rejected') {
    finishWithTransportFailure(scan, 'failed', event.message || 'The request could not be queued.');
  } else if (event.type === 'interrupted') {
    finishWithTransportFailure(scan, 'interrupted', event.message || 'The diagnostic stream was interrupted.');
  }
}

export function updateProgressBar(target) {
  const card = getCard(target);
  const scan = getScan(target);
  if (!card || !scan) return;
  const bar = card.querySelector('.result-card__progress i');
  const wrapper = card.querySelector('.result-card__progress');
  const percent = scan.total > 0 ? Math.min(100, (scan.completed / scan.total) * 100) : 0;
  bar.style.width = `${percent}%`;
  wrapper.setAttribute('aria-valuenow', String(Math.round(percent)));
  wrapper.setAttribute('aria-valuetext', `${Math.round(percent)} percent complete`);
}

function updateFindingCount(target) {
  const card = getCard(target);
  const scan = getScan(target);
  if (!card || !scan) return;
  const count = scan.failures.size + scan.findings.size;
  const badge = card.querySelector('.finding-count');
  badge.hidden = count === 0;
  badge.textContent = `${count} finding${count === 1 ? '' : 's'}`;
  badge.className = `badge finding-count ${count > 0 ? 'badge--warn' : ''}`;
}

/* ---------- incoming message routing ---------- */

function currentScanForMessage(msg) {
  if (typeof msg.request_id !== 'string' || !msg.request_id) return null;
  const scan = getScanByRequestID(msg.request_id);
  if (!scan) return null;
  if (['completed', 'failed', 'interrupted'].includes(scan.status)) return null;
  if (msg.target !== scan.target) return null;
  return scan;
}

export function routeMessage(msg) {
  if (msg.type === 'log') {
    const scan = currentScanForMessage(msg);
    if (!scan) return false;
    appendLog(scan.target, String(msg.data));
    return true;
  }
  if (msg.type === 'error') {
    const message = typeof msg.data === 'string' ? msg.data : 'The server rejected a diagnostic request.';
    if (!msg.request_id) {
      appendLog('SYSTEM', message);
      announce(message);
      return true;
    }
    const requestScan = getScanByRequestID(msg.request_id);
    const scan = msg.target
      ? currentScanForMessage(msg)
      : (requestScan && !['completed', 'failed', 'interrupted'].includes(requestScan.status)
        ? requestScan : null);
    if (!scan) return false;
    finishWithTransportFailure(scan, 'failed', message, 'server_rejected');
    return true;
  }
  if (msg.type === 'done') {
    const scan = currentScanForMessage(msg);
    if (scan) {
      const section = [...(getCard(scan.target)?.querySelectorAll('.service-section') || [])]
        .find((candidate) => candidate.dataset.service === msg.service);
      if (section?.querySelector('.skel')) {
        const profileOnly = scan.targetProfile?.valid && !scan.targetProfile?.networkable;
        section.innerHTML = skippedDetails(msg.service, profileOnly ? 'profile-only' : '');
      }
      if (!scan.completedServices.has(msg.service)) {
        scan.completedServices.add(msg.service);
        scan.completed = scan.completedServices.size;
      }
      updateProgressBar(scan.target);
      const failed = scan.failures.has(msg.service);
      const flagged = scan.findings.has(msg.service);
      appendLog(scan.target, failed
        ? `Module ${serviceLabel(msg.service)} failed.`
        : `Module ${serviceLabel(msg.service)} complete${flagged ? ' (findings)' : ''}.`);
    }
    return Boolean(scan);
  }
  if (msg.type === 'all_done') {
    const scan = currentScanForMessage(msg);
    if (scan) handleAllDone(scan);
    return Boolean(scan);
  }
  if (msg.type === 'result') {
    const scan = currentScanForMessage(msg);
    if (scan) handleResult(msg, scan);
    return Boolean(scan);
  }
  return false;
}

function handleAllDone(scan) {
  const { target } = scan;
  const card = getCard(target);
  if (!card) return;
  scan.completed = scan.total;
  const bar = card.querySelector('.result-card__progress i');
  bar.style.width = '100%';
  const progress = card.querySelector('.result-card__progress');
  progress.setAttribute('aria-valuenow', '100');
  const badge = card.querySelector('.status-badge');
  const invalidTarget = scan.targetProfile && !scan.targetProfile.valid;
  const profileOnly = scan.targetProfile?.valid && !scan.targetProfile.networkable;
  const problems = scan.failures.size + scan.findings.size;
  updateFindingCount(target);
  if (invalidTarget) {
    setScanStatusByRequestID(scan.requestID, 'failed', 'invalid_target');
    badge.textContent = 'INVALID TARGET';
    badge.className = 'badge badge--err status-badge';
    progress.setAttribute('aria-valuetext', 'Target invalid; diagnostics were not run');
  } else if (profileOnly) {
    setScanStatusByRequestID(scan.requestID, 'completed', 'profile_only');
    badge.textContent = 'PROFILE ONLY';
    badge.className = 'badge badge--skip status-badge';
    progress.setAttribute('aria-valuetext', 'Profile complete; active modules skipped');
  } else {
    setScanStatusByRequestID(scan.requestID, 'completed', problems > 0 ? 'findings' : 'clean');
    badge.textContent = problems > 0 ? 'COMPLETE · FINDINGS' : 'COMPLETE';
    badge.className = `badge status-badge ${problems > 0 ? 'badge--warn' : 'badge--ok'}`;
    progress.setAttribute('aria-valuetext', 'Diagnostics complete');
  }
  card.setAttribute('aria-busy', 'false');
  card.dataset.scanStatus = scan.status;
  const rescan = card.querySelector('[data-card-action="rescan"]');
  if (rescan) rescan.disabled = false;
  card.querySelectorAll('.service-section').forEach((section) => {
    if (section.querySelector('.skel')) {
      const reason = invalidTarget ? 'invalid-target' : (profileOnly ? 'profile-only' : '');
      section.innerHTML = skippedDetails(section.dataset.service, reason);
    }
  });
  if (invalidTarget) {
    appendLog(target, 'The target is invalid; active diagnostics were not run.');
    announce(`Diagnostics failed for ${target}: invalid target.`);
  } else if (profileOnly) {
    appendLog(target, 'Target profile complete; active diagnostics were skipped.');
    announce(`Target profile completed for ${target}; active diagnostics were skipped.`);
  } else {
    appendLog(target, problems > 0 ? `Diagnostics finished with ${problems} finding(s).` : 'All diagnostics finished.');
    announce(problems > 0
      ? `Diagnostics completed for ${target} with ${problems} findings.`
      : `Diagnostics completed for ${target}.`);
  }
  updateWorkspaceState();
}

function handleResult(msg, scan) {
  const { target } = scan;
  const card = getCard(target);
  if (!card) return;
  const section = [...card.querySelectorAll('.service-section')]
    .find((candidate) => candidate.dataset.service === msg.service);
  if (!section) return;
  if (msg.service === 'target' && isPlainObject(msg.data)) {
    scan.targetProfile = {
      valid: msg.data.valid === true,
      networkable: msg.data.networkable === true,
    };
  }
  const hardFailure = resultHasError(msg.data)
    || (msg.service === 'whois' && typeof msg.data === 'string' && /^(?:whois\s+)?error:/i.test(msg.data.trim()));
  if (hardFailure) {
    scan.failures.add(msg.service);
    scan.findings.delete(msg.service);
  }
  appendLog(target, `Receiving ${serviceLabel(msg.service)} stream...`);
  getResults(target)[msg.service] = msg.data;

  if (msg.service === 'ping') destroySectionChart(section);
  section.innerHTML = renderService(msg.service, msg.data, target, section);

  const rendered = section.querySelector('.status-dot')?.getAttribute('data-status');
  if (rendered === 'error' && !scan.failures.has(msg.service)) {
    scan.findings.add(msg.service);
  } else if (rendered !== 'error' && !scan.failures.has(msg.service)) {
    scan.findings.delete(msg.service);
  }
  updateFindingCount(target);

  // streaming ping chart
  if (msg.service === 'ping' && section.dataset.chartId) {
    mountPingChart(section);
  }
  wireCopyable(section);
  updateWorkspaceState();
}

function mountPingChart(section) {
  const canvas = document.getElementById(section.dataset.chartId);
  if (!canvas || !window.Chart) return;
  let rtts = [];
  try { rtts = JSON.parse(section.dataset.chartRtts || '[]'); } catch { rtts = []; }
  if (!rtts.length) return;
  const existing = section._pingChart;
  if (existing) {
    existing.data.labels = rtts.map((_, i) => `#${i + 1}`);
    existing.data.datasets[0].data = rtts;
    existing.update('none');
    return;
  }
  const chart = new window.Chart(canvas, {
    type: 'line',
    data: {
      labels: rtts.map((_, i) => `#${i + 1}`),
      datasets: [{
        data: rtts,
        borderColor: '#00f48e',
        backgroundColor: 'rgba(0,244,142,0.1)',
        borderWidth: 1,
        pointRadius: 2,
        pointBackgroundColor: '#00ff3c',
        tension: 0.2,
        fill: true,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: 'rgba(0,244,142,0.7)', font: { size: 9, family: 'Cascadia Mono' } }, grid: { color: '#0d2417' } },
        y: { ticks: { color: 'rgba(0,244,142,0.7)', font: { size: 9, family: 'Cascadia Mono' } }, grid: { color: '#0d2417' } },
      },
    },
  });
  section._pingChart = chart;
  registerChart(section.dataset.chartId, { destroy: () => chart.destroy() });
}

/* ---------- reports & export ---------- */

function copyTargetReport(card) {
  const target = card.querySelector('.result-card__target').innerText;
  const record = getAllResultsData().find((item) => item.target === target);
  let text = `DIAGNOSTIC REPORT FOR: ${target}\nGenerated: ${new Date().toLocaleString()}\n`;
  if (record) {
    text += `Status: ${record.status.toUpperCase()}${record.outcome ? ` (${record.outcome})` : ''}\nPartial: ${record.partial ? 'yes' : 'no'}\n`;
  }
  text += `${'-'.repeat(42)}\n\n`;
  card.querySelectorAll('.service-section > details').forEach((details) => {
    const summary = details.querySelector(':scope > summary');
    if (!summary) return;
    const title = summary.innerText.replace(/[^a-zA-Z0-9 /&_-]/g, '').trim();
    let body = '';
    Array.from(details.childNodes).forEach((node) => {
      if (node.nodeName.toLowerCase() === 'summary') return;
      const clone = node.cloneNode(true);
      clone.querySelectorAll?.('.copy-trigger').forEach((button) => button.remove());
      body += `${clone.textContent || ''}\n`;
    });
    body = body.trim();
    if (body) text += `[${title}]\n${body}\n\n`;
  });
  copyText(text.trim(), 'Report copied');
}

export function exportJSON() {
  const data = getAllResultsData();
  if (!hasExportableResults()) { announce('There are no results to export yet.'); return; }
  downloadBlob(JSON.stringify(data, null, 2), 'application/json', `scan_results_${Date.now()}.json`);
  announce('JSON export downloaded.');
}

export function copyAllJSON() {
  const data = getAllResultsData();
  if (!hasExportableResults()) { announce('There are no results to copy yet.'); return; }
  copyText(JSON.stringify(data, null, 2), 'All results copied as JSON');
}

export function exportCSV() {
  const data = getAllResultsData();
  if (!hasExportableResults()) { announce('There are no results to export yet.'); return; }
  const cell = (value) => {
    let text = String(value ?? '');
    if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  };
  let csv = 'Target,Request ID,Status,Outcome,Partial,Started At,Completed At,Progress,Config,Service,Data\n';
  data.forEach((record) => {
    const entries = Object.entries(record.services);
    (entries.length ? entries : [['', '']]).forEach(([service, result]) => {
      const progress = `${record.progress.completed}/${record.progress.total} (${record.progress.percent}%)`;
      csv += [
        record.target,
        record.request_id,
        record.status,
        record.outcome,
        record.partial,
        record.started_at,
        record.completed_at,
        progress,
        JSON.stringify(record.config),
        service,
        service ? JSON.stringify(result) : '',
      ].map(cell).join(',') + '\n';
    });
  });
  downloadBlob(csv, 'text/csv', `scan_results_${Date.now()}.csv`);
  announce('CSV export downloaded.');
}

export { clearWorkspace };
