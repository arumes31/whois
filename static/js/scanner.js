import {
  escapeHTML, fetchWithCSRF, readResponse, wireCopyable,
} from './util.js';

const form = document.getElementById('scanForm');
const indicator = document.getElementById('scanIndicator');
const results = document.getElementById('scanResults');
const submit = document.getElementById('scanSubmit');
const errorSummary = document.getElementById('scannerErrorSummary');

if (form && indicator && results && submit) {
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const target = form.elements.target.value.trim();
    if (!target) {
      errorSummary.hidden = false;
      errorSummary.innerHTML = '<strong>Scan could not start.</strong> <a href="#scanTarget">Enter a target IP address or domain.</a>';
      form.elements.target.setAttribute('aria-invalid', 'true');
      errorSummary.focus();
      return;
    }
    errorSummary.hidden = true;
    form.elements.target.removeAttribute('aria-invalid');
    indicator.hidden = false;
    submit.disabled = true;
    submit.setAttribute('aria-busy', 'true');
    submit.textContent = 'SCANNING…';
    results.replaceChildren();
    try {
      const response = await fetchWithCSRF('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          target,
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
      submit.removeAttribute('aria-busy');
      submit.textContent = 'INITIATE SCAN';
    }
  });
}
