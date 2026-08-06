import {
  escapeHTML, fetchWithCSRF, readResponse, wireCopyable,
} from './util.js';

const form = document.getElementById('scanForm');
const indicator = document.getElementById('scanIndicator');
const results = document.getElementById('scanResults');
const submit = document.getElementById('scanSubmit');

if (form && indicator && results && submit) {
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    indicator.hidden = false;
    submit.disabled = true;
    results.replaceChildren();
    try {
      const response = await fetchWithCSRF('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          target: form.elements.target.value,
          ports: form.elements.ports.value,
        }),
      });
      results.innerHTML = await readResponse(response);
      wireCopyable(results);
    } catch (error) {
      results.innerHTML = `<div class="alert-err" role="alert">Scan request failed: ${escapeHTML(error.message || error)}</div>`;
    } finally {
      indicator.hidden = true;
      submit.disabled = false;
    }
  });
}
