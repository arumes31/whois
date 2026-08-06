import { escapeHTML, fetchWithCSRF, readResponse } from './util.js';

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
    } catch (error) {
      output.innerHTML = `<div class="alert-err" role="alert">${escapeHTML(error.message || error)}</div>`;
    } finally {
      button.disabled = false;
    }
  });
}
