// Shared page chrome: mandatory disclosure and declarative confirmations.
import { closeDialog, openDialog } from './util.js';

const DISCLOSURE_KEY = 'whois_disclosure_accepted';

function initDisclosure() {
  const backdrop = document.getElementById('disclosureBackdrop');
  const accept = document.getElementById('disclosureAccept');
  if (!backdrop || !accept) return;

  let accepted = false;
  try { accepted = window.localStorage.getItem(DISCLOSURE_KEY) === 'true'; } catch { /* storage unavailable */ }
  if (!accepted) {
    openDialog(backdrop, { initialFocus: accept, closeOnEscape: false });
  }

  accept.addEventListener('click', () => {
    try { window.localStorage.setItem(DISCLOSURE_KEY, 'true'); } catch { /* storage unavailable */ }
    closeDialog(backdrop);
    document.getElementById('main-content')?.focus();
  });
}

function initConfirmations() {
  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });
}

initDisclosure();
initConfirmations();
