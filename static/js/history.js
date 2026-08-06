// Scan history viewer + quick tools, rendered into the shared modal.
import {
  closeDialog, escapeHTML, fetchWithCSRF, openDialog, readResponse, announce, wireCopyable,
} from './util.js';

let backdrop;
let titleEl;
let bodyEl;
let activeRequest;
let modalGeneration = 0;

function beginModalContent() {
  modalGeneration += 1;
  activeRequest?.abort();
  activeRequest = undefined;
  return modalGeneration;
}

function beginModalRequest() {
  activeRequest?.abort();
  activeRequest = new AbortController();
  return activeRequest;
}

function requestIsCurrent(generation, controller) {
  return generation === modalGeneration
    && controller === activeRequest
    && backdrop?.classList.contains('is-open');
}

function finishModalRequest(controller) {
  if (activeRequest === controller) activeRequest = undefined;
}

export function initModal() {
  backdrop = document.getElementById('modalBackdrop');
  titleEl = document.getElementById('modalTitle');
  bodyEl = document.getElementById('modalBody');
  document.getElementById('modalClose').addEventListener('click', closeModal);
  backdrop.addEventListener('click', (event) => {
    if (event.target === backdrop) closeModal();
  });
  window.addEventListener('console:history', (event) => {
    fetchHistory(event.detail.target);
  });
}

export function openModal(title, initialFocus = document.getElementById('modalClose')) {
  titleEl.textContent = title;
  openDialog(backdrop, {
    initialFocus,
    onRequestClose: closeModal,
  });
}

export function closeModal() {
  beginModalContent();
  closeDialog(backdrop);
}

function setBody(html) { bodyEl.innerHTML = html; }

async function fetchHistory(target) {
  const generation = beginModalContent();
  openModal(`HISTORY: ${target}`);
  setBody('<div class="live-log__empty">Loading archive…</div>');
  const controller = beginModalRequest();
  try {
    const resp = await fetchWithCSRF(`/history?item=${encodeURIComponent(target)}`, {
      signal: controller.signal,
    });
    const data = await readResponse(resp, { json: true });
    if (!requestIsCurrent(generation, controller)) return;
    if (data.error) {
      setBody(`<div class="alert-err">${escapeHTML(data.error)}</div>`);
      return;
    }
    if (!data.entries || data.entries.length === 0) {
      setBody('<div class="alert-ok">No historical data found for this target.</div>');
      return;
    }
    let html = '';
    if (data.diffs && data.diffs.length > 0) {
      html += `<h3 style="color:var(--red);font-size:10px;letter-spacing:.24em;margin:0 0 8px">RECENT CHANGES DETECTED</h3><div class="diff-viewer">`;
      data.diffs.forEach((diff) => {
        if (diff === 'No changes') return;
        diff.split('\n').forEach((line) => {
          let cls = '';
          if (line.startsWith('+') && !line.startsWith('+++')) cls = 'diff-line-added';
          else if (line.startsWith('-') && !line.startsWith('---')) cls = 'diff-line-removed';
          else if (line.startsWith('@@')) cls = 'diff-line-info';
          if (line.trim()) html += `<div class="${cls}">${escapeHTML(line)}</div>`;
        });
      });
      html += '</div>';
    }
    html += `<h3 style="font-size:10px;letter-spacing:.24em;color:var(--phos-70);margin:16px 0 8px">FULL SCAN ARCHIVE</h3><div class="history-grid">`;
    data.entries.forEach((entry) => {
      const date = new Date(entry.timestamp).toLocaleString();
      let records = '';
      try {
        const parsed = JSON.parse(entry.result);
        records = Object.keys(parsed).map((k) => `<span class="chip">${escapeHTML(k)}</span>`).join(' ');
      } catch { records = ''; }
      html += `<div class="history-item"><time>${escapeHTML(date)}</time><div class="chips">${records}</div>
        <details><summary><small>SNAPSHOT</small></summary><pre class="raw-block">${escapeHTML(entry.result)}</pre></details></div>`;
    });
    html += '</div>';
    setBody(html);
  } catch (err) {
    if (err.name !== 'AbortError' && requestIsCurrent(generation, controller)) {
      setBody(`<div class="alert-err">History request failed: ${escapeHTML(err.message)}</div>`);
    }
  } finally {
    finishModalRequest(controller);
  }
}

/* ---------- quick tools ---------- */

export function openTool(name) {
  if (name === 'dns') {
    const generation = beginModalContent();
    setBody(`
      <form id="toolDnsForm">
        <div class="form-field">
          <label for="toolDnsTarget">DOMAIN / HOSTNAME</label>
          <input id="toolDnsTarget" class="text-input" placeholder="example.com" autocomplete="off" spellcheck="false" required>
        </div>
        <div class="form-field">
          <label for="toolDnsType">RECORD TYPE</label>
          <input id="toolDnsType" class="text-input" value="A" autocomplete="off" spellcheck="false">
        </div>
        <button type="submit" class="btn btn--solid">RESOLVE</button>
      </form>
      <div id="toolResult" style="margin-top:16px"></div>`);
    openModal('SINGLE DNS LOOKUP', '#toolDnsTarget');
    document.getElementById('toolDnsForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      const target = document.getElementById('toolDnsTarget').value.trim();
      const type = document.getElementById('toolDnsType').value.trim() || 'A';
      const out = document.getElementById('toolResult');
      out.innerHTML = '<div class="live-log__empty">Resolving…</div>';
      const controller = beginModalRequest();
      try {
        const resp = await fetchWithCSRF('/dns_lookup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ domain: target, type }),
          signal: controller.signal,
        });
        const html = await readResponse(resp);
        if (!requestIsCurrent(generation, controller)) return;
        out.innerHTML = html;
        wireCopyable(out);
      } catch (err) {
        if (err.name !== 'AbortError' && requestIsCurrent(generation, controller)) {
          out.innerHTML = `<div class="alert-err">${escapeHTML(err.message)}</div>`;
        }
      } finally {
        finishModalRequest(controller);
      }
    });
  } else if (name === 'mac') {
    const generation = beginModalContent();
    setBody(`
      <form id="toolMacForm">
        <div class="form-field">
          <label for="toolMacTarget">MAC ADDRESS</label>
          <input id="toolMacTarget" class="text-input" placeholder="00:1A:2B:3C:4D:5E" autocomplete="off" spellcheck="false" required>
        </div>
        <button type="submit" class="btn btn--solid">IDENTIFY VENDOR</button>
      </form>
      <div id="toolResult" style="margin-top:16px"></div>`);
    openModal('MAC VENDOR LOOKUP', '#toolMacTarget');
    document.getElementById('toolMacForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      const mac = document.getElementById('toolMacTarget').value.trim();
      const out = document.getElementById('toolResult');
      out.innerHTML = '<div class="live-log__empty">Querying OUI database…</div>';
      const controller = beginModalRequest();
      try {
        const resp = await fetchWithCSRF('/mac_lookup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ mac }),
          signal: controller.signal,
        });
        const html = await readResponse(resp);
        if (!requestIsCurrent(generation, controller)) return;
        out.innerHTML = html;
        wireCopyable(out);
      } catch (err) {
        if (err.name !== 'AbortError' && requestIsCurrent(generation, controller)) {
          out.innerHTML = `<div class="alert-err">${escapeHTML(err.message)}</div>`;
        }
      } finally {
        finishModalRequest(controller);
      }
    });
  }
}

export { announce };
