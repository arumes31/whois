// Scan history viewer + quick tools, rendered into the shared modal.
import {
  closeDialog, escapeHTML, fetchWithCSRF, openDialog, readResponse, announce, wireCopyable, canonicalTargetIdentity,
} from './util.js';
import { saveSettings, updateModuleCount } from './store.js';

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

export function prepareLookupToolRequest(name, value, { routingEnabled = false, routingConsent = false } = {}) {
  const raw = String(value || '').trim();
  if (name === 'subnet') {
    return canonicalTargetIdentity(raw).startsWith('prefix|')
      ? { target: raw } : { error: 'Enter an IPv4 or IPv6 address with a prefix length, such as 192.168.1.129/24 or 2001:db8::1/64.' };
  }
  if (name === 'asn') {
    if (!routingEnabled) return { error: 'ASN lookup is disabled by the server. Enable BGP ROUTING to use this provider lookup.' };
    if (!routingConsent) return { error: 'Select the RIPEstat checkbox to allow this external lookup.' };
    const identity = canonicalTargetIdentity(/^\d+$/.test(raw) ? `AS${raw}` : raw);
    return identity.startsWith('asn|') ? { target: identity.slice(4) } : { error: 'Enter an ASN from 1 to 4294967295, such as AS13335 or 13335.' };
  }
  return { error: 'Unknown lookup tool.' };
}

function openLookupTool(name) {
  beginModalContent();
  const isASN = name === 'asn';
  const routingBox = document.getElementById('cfg-routing');
  const routingEnabled = Boolean(routingBox && !routingBox.disabled);
  setBody(`
    <form id="toolLookupForm">
      <div class="form-field">
        <label for="toolLookupTarget">${isASN ? 'AUTONOMOUS SYSTEM NUMBER' : 'IP ADDRESS / PREFIX LENGTH'}</label>
        <input id="toolLookupTarget" class="text-input" placeholder="${isASN ? 'AS13335 or 13335' : '192.168.1.129/24 or 2001:db8::1/64'}" aria-describedby="toolLookupHelp toolLookupError" autocomplete="off" autocapitalize="none" spellcheck="false" required>
        <p id="toolLookupHelp" class="field-help">${isASN
          ? (routingEnabled ? 'Look up holder, origin visibility and prefixes observed during the requested period. Results appear in the workspace.' : 'BGP routing is disabled by the server. Ask the operator to enable it before using this external lookup.')
          : 'Calculate the network, address range and exact counts locally. No diagnostic module or external provider is needed. Results appear in the workspace.'}</p>
      </div>
      ${isASN ? `<label class="tool-consent" for="toolRoutingConsent"><input type="checkbox" id="toolRoutingConsent" aria-describedby="toolLookupHelp"${routingEnabled && routingBox.checked ? ' checked' : ''}${routingEnabled ? '' : ' disabled'}> Send this ASN to RIPEstat and enable BGP ROUTING for this browser.</label>` : ''}
      <p id="toolLookupError" class="field-error" role="alert"></p>
      <button type="submit" class="btn btn--solid"${isASN && !routingEnabled ? ' disabled' : ''}>${isASN ? 'LOOK UP ASN' : 'CALCULATE SUBNET'}</button>
    </form>`);
  openModal(isASN ? 'ASN LOOKUP' : 'SUBNET CALCULATOR', '#toolLookupTarget');
  document.getElementById('toolLookupForm').addEventListener('submit', event => {
    event.preventDefault();
    const input = document.getElementById('toolLookupTarget');
    const request = prepareLookupToolRequest(name, input.value, {
      routingEnabled: Boolean(routingBox && !routingBox.disabled),
      routingConsent: document.getElementById('toolRoutingConsent')?.checked === true,
    });
    if (request.error) {
      document.getElementById('toolLookupError').textContent = request.error;
      input.focus();
      return;
    }
    if (isASN) {
      routingBox.checked = true;
      saveSettings();
      updateModuleCount();
      document.dispatchEvent(new CustomEvent('console:modules-changed'));
    }
    closeModal();
    window.dispatchEvent(new CustomEvent('console:query-target', { detail: { target: request.target } }));
  });
}

export function openTool(name) {
  if (name === 'subnet' || name === 'asn') {
    openLookupTool(name);
  } else if (name === 'dns') {
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
