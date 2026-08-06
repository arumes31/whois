import {
  announce, copyText, downloadBlob, escapeHTML, fetchWithCSRF, readResponse, toast,
} from './util.js';

const AUDIT_KEY = 'whois_config_activity';

function audit(action) {
  let entries = [];
  try { entries = JSON.parse(window.localStorage.getItem(AUDIT_KEY) || '[]'); } catch { entries = []; }
  entries.push({ action, at: new Date().toISOString() });
  entries = entries.slice(-10);
  try { window.localStorage.setItem(AUDIT_KEY, JSON.stringify(entries)); } catch { /* unavailable */ }
  renderAudit(entries);
}

function renderAudit(provided) {
  const list = document.getElementById('configAuditLog');
  if (!list) return;
  let entries = provided;
  if (!entries) {
    try { entries = JSON.parse(window.localStorage.getItem(AUDIT_KEY) || '[]'); } catch { entries = []; }
  }
  if (!Array.isArray(entries) || entries.length === 0) return;
  list.innerHTML = entries.slice().reverse().map((entry) => `<li><time datetime="${escapeHTML(entry.at)}">${escapeHTML(new Date(entry.at).toLocaleString())}</time> ${escapeHTML(entry.action)}</li>`).join('');
}

const button = document.getElementById('geoUpdateBtn');
const output = document.getElementById('geoUpdateRes');

if (button && output) {
  button.addEventListener('click', async () => {
    button.disabled = true;
    output.innerHTML = '<span class="live-log__empty">Updating database…</span>';
    try {
      const response = await fetchWithCSRF('/config/update-geo', { method: 'POST' });
      const payload = await readResponse(response);
      const text = typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2);
      output.innerHTML = `<pre class="raw-block">${escapeHTML(text)}</pre>`;
      const updated = new Date();
      window.sessionStorage.setItem('whois_geo_updated_at', updated.toISOString());
      document.getElementById('geoFreshness').textContent = updated.toLocaleString();
      audit('GeoIP database update requested');
    } catch (error) {
      output.innerHTML = `<div class="alert-err" role="alert">${escapeHTML(error.message || error)}</div>`;
    } finally {
      button.disabled = false;
    }
  });
}

const lastGeoUpdate = window.sessionStorage.getItem('whois_geo_updated_at');
if (lastGeoUpdate) document.getElementById('geoFreshness').textContent = new Date(lastGeoUpdate).toLocaleString();

document.getElementById('healthTestBtn')?.addEventListener('click', async (event) => {
  const healthButton = event.currentTarget;
  healthButton.disabled = true;
  try {
    const response = await fetchWithCSRF('/health', { cache: 'no-store' });
    await readResponse(response);
    toast('Service health check passed');
    audit('Service health check passed');
  } catch (error) {
    output.innerHTML = `<div class="alert-err" role="alert">Health check failed: ${escapeHTML(error.message || error)}</div>`;
    audit('Service health check failed');
  } finally {
    healthButton.disabled = false;
  }
});

const monitorForm = document.getElementById('monitorForm');
const monitorInput = document.getElementById('monitorItem');
const saveBar = document.getElementById('configSaveBar');
const syncDirty = () => {
  if (saveBar) saveBar.hidden = !monitorInput?.value.trim();
  monitorInput?.removeAttribute('aria-invalid');
};
monitorInput?.addEventListener('input', syncDirty);
document.getElementById('configDiscard')?.addEventListener('click', () => {
  monitorForm?.reset();
  syncDirty();
  monitorInput?.focus();
  announce('Unsaved monitoring target discarded.');
});
monitorForm?.addEventListener('submit', (event) => {
  const value = monitorInput.value.trim();
  if (!value || /\s/.test(value)) {
    event.preventDefault();
    monitorInput.setAttribute('aria-invalid', 'true');
    document.getElementById('monitorItemHelp').textContent = 'Enter one domain or IP address without spaces.';
    monitorInput.focus();
    return;
  }
  audit(`Submitted add request for ${value}`);
  monitorForm.querySelectorAll('button').forEach((control) => { control.disabled = true; });
});

let loginAttempt = '';
try { loginAttempt = window.sessionStorage.getItem('whois_login_attempted_at') || ''; } catch { /* unavailable */ }
if (loginAttempt) {
  document.getElementById('sessionLastLogin').textContent = `Signed in from this browser at ${new Date(loginAttempt).toLocaleString()}.`;
  try { window.sessionStorage.removeItem('whois_login_attempted_at'); } catch { /* unavailable */ }
}

const search = document.getElementById('monitorSearch');
const sort = document.getElementById('monitorSort');
const list = document.getElementById('monitoredList');
function filterAndSort() {
  if (!list) return;
  const query = search.value.trim().toLowerCase();
  const rows = [...list.querySelectorAll('.monitor-row')];
  rows.sort((a, b) => a.dataset.monitorTarget.localeCompare(b.dataset.monitorTarget) * (sort.value === 'desc' ? -1 : 1));
  rows.forEach((row) => {
    row.hidden = row.dataset.pendingRemoval === 'true' || !row.dataset.monitorTarget.toLowerCase().includes(query);
    list.appendChild(row);
  });
  const visible = rows.filter((row) => !row.hidden).length;
  document.getElementById('monitoredVisibleCount').textContent = String(visible);
  document.getElementById('monitorEmptyFilter').hidden = visible > 0;
}
search?.addEventListener('input', filterAndSort);
sort?.addEventListener('change', filterAndSort);

function selectedTargets() {
  return [...document.querySelectorAll('.monitor-row:not([hidden]) .monitor-select:checked')]
    .map((checkbox) => checkbox.closest('.monitor-row').dataset.monitorTarget);
}

function syncSelection() {
  const selected = selectedTargets();
  document.getElementById('monitorSelectionCount')?.replaceChildren(document.createTextNode(`${selected.length} selected`));
  ['monitorCopySelected', 'monitorExportSelected'].forEach((id) => {
    const control = document.getElementById(id);
    if (control) control.disabled = selected.length === 0;
  });
}

document.querySelectorAll('.monitor-select').forEach((checkbox) => checkbox.addEventListener('change', syncSelection));
document.getElementById('monitorSelectAll')?.addEventListener('click', (event) => {
  const visible = [...document.querySelectorAll('.monitor-row:not([hidden]) .monitor-select')];
  const select = visible.some((checkbox) => !checkbox.checked);
  visible.forEach((checkbox) => { checkbox.checked = select; });
  event.currentTarget.setAttribute('aria-pressed', String(select));
  event.currentTarget.textContent = select ? 'Clear visible' : 'Select visible';
  syncSelection();
});
document.getElementById('monitorCopySelected')?.addEventListener('click', () => copyText(selectedTargets().join('\n'), 'Selected targets copied'));
document.getElementById('monitorExportSelected')?.addEventListener('click', () => {
  downloadBlob(JSON.stringify({ monitored: selectedTargets() }, null, 2), 'application/json', `monitored_targets_${Date.now()}.json`);
  announce('Selected monitored targets exported.');
});

document.querySelectorAll('[data-remove-monitor]').forEach((removeForm) => {
  removeForm.addEventListener('submit', (event) => {
    event.preventDefault();
    const row = removeForm.closest('.monitor-row');
    const target = row.dataset.monitorTarget;
    row.dataset.pendingRemoval = 'true';
    row.hidden = true;
    let committed = false;
    const timer = window.setTimeout(() => {
      committed = true;
      audit(`Removed monitoring target ${target}`);
      removeForm.submit();
    }, 5000);
    const toastElement = document.getElementById('toast');
    toastElement.replaceChildren(document.createTextNode(`${target} scheduled for removal. `));
    const undo = document.createElement('button');
    undo.type = 'button';
    undo.className = 'toast__action';
    undo.textContent = 'Undo';
    undo.addEventListener('click', () => {
      if (committed) return;
      window.clearTimeout(timer);
      delete row.dataset.pendingRemoval;
      row.hidden = false;
      toastElement.classList.remove('is-show');
      filterAndSort();
      announce(`${target} was not removed.`);
      row.querySelector('button')?.focus();
    });
    toastElement.appendChild(undo);
    toastElement.classList.add('is-show');
    window.setTimeout(() => { if (!committed) toastElement.classList.remove('is-show'); }, 4800);
    filterAndSort();
  });
});

renderAudit();
