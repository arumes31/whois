// Scan history viewer + quick tools, rendered into the shared modal.
import { escapeHTML, announce, wireCopyable } from './util.js';

let modal;
let backdrop;
let titleEl;
let bodyEl;

export function initModal() {
  backdrop = document.getElementById('modalBackdrop');
  titleEl = document.getElementById('modalTitle');
  bodyEl = document.getElementById('modalBody');
  document.getElementById('modalClose').addEventListener('click', closeModal);
  backdrop.addEventListener('click', (event) => {
    if (event.target === backdrop) closeModal();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && backdrop.classList.contains('is-open')) closeModal();
  });
  window.addEventListener('console:history', (event) => {
    fetchHistory(event.detail.target);
  });
}

export function openModal(title) {
  titleEl.textContent = title;
  backdrop.classList.add('is-open');
  document.body.style.overflow = 'hidden';
}

export function closeModal() {
  backdrop.classList.remove('is-open');
  document.body.style.overflow = '';
}

function setBody(html) { bodyEl.innerHTML = html; }

async function fetchHistory(target) {
  openModal(`HISTORY: ${target}`);
  setBody('<div class="live-log__empty">Loading archive…</div>');
  try {
    const resp = await fetch(`/history?item=${encodeURIComponent(target)}`);
    const data = await resp.json();
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
    setBody(`<div class="alert-err">History request failed: ${escapeHTML(err.message)}</div>`);
  }
}

/* ---------- quick tools ---------- */

export function openTool(name) {
  if (name === 'dns') {
    openModal('SINGLE DNS LOOKUP');
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
    document.getElementById('toolDnsForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      const target = document.getElementById('toolDnsTarget').value.trim();
      const type = document.getElementById('toolDnsType').value.trim() || 'A';
      const out = document.getElementById('toolResult');
      out.innerHTML = '<div class="live-log__empty">Resolving…</div>';
      try {
        const resp = await fetch('/dns_lookup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ domain: target, type }),
        });
        out.innerHTML = await resp.text();
        wireCopyable(out);
      } catch (err) {
        out.innerHTML = `<div class="alert-err">${escapeHTML(err.message)}</div>`;
      }
    });
    document.getElementById('toolDnsTarget').focus();
  } else if (name === 'mac') {
    openModal('MAC VENDOR LOOKUP');
    setBody(`
      <form id="toolMacForm">
        <div class="form-field">
          <label for="toolMacTarget">MAC ADDRESS</label>
          <input id="toolMacTarget" class="text-input" placeholder="00:1A:2B:3C:4D:5E" autocomplete="off" spellcheck="false" required>
        </div>
        <button type="submit" class="btn btn--solid">IDENTIFY VENDOR</button>
      </form>
      <div id="toolResult" style="margin-top:16px"></div>`);
    document.getElementById('toolMacForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      const mac = document.getElementById('toolMacTarget').value.trim();
      const out = document.getElementById('toolResult');
      out.innerHTML = '<div class="live-log__empty">Querying OUI database…</div>';
      try {
        const resp = await fetch('/mac_lookup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ mac }),
        });
        out.innerHTML = await resp.text();
        wireCopyable(out);
      } catch (err) {
        out.innerHTML = `<div class="alert-err">${escapeHTML(err.message)}</div>`;
      }
    });
    document.getElementById('toolMacTarget').focus();
  }
}

export { announce };
