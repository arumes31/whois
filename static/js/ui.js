// Shared page chrome: navigation, connectivity, privacy, and disclosures.
import { announce, closeDialog, openDialog, toast } from './util.js';

const DISCLOSURE_KEY = 'whois_disclosure_accepted';
const DISCLOSURE_VERSION = '2026-08-06';
const NOTIFICATION_KEY = 'whois_scan_notifications';

function closeMobileDrawer() {
  const drawer = document.getElementById('mobileDrawer');
  const toggle = document.getElementById('navToggle');
  if (!drawer?.classList.contains('is-open')) return;
  closeDialog(drawer);
  drawer.inert = true;
  toggle?.setAttribute('aria-expanded', 'false');
}

function initDisclosure() {
  const backdrop = document.getElementById('disclosureBackdrop');
  const accept = document.getElementById('disclosureAccept');
  if (!backdrop || !accept) return;

  let accepted = null;
  try { accepted = JSON.parse(window.localStorage.getItem(DISCLOSURE_KEY) || 'null'); } catch { accepted = null; }
  const acceptedCurrent = accepted?.version === DISCLOSURE_VERSION;
  const meta = document.getElementById('disclosureAcceptedAt');
  if (meta && accepted?.accepted_at) meta.textContent = `Last accepted on this device: ${new Date(accepted.accepted_at).toLocaleString()}`;
  if (!acceptedCurrent) {
    openDialog(backdrop, { initialFocus: accept, closeOnEscape: false });
  }

  accept.addEventListener('click', () => {
    const record = { version: DISCLOSURE_VERSION, accepted_at: new Date().toISOString() };
    try { window.localStorage.setItem(DISCLOSURE_KEY, JSON.stringify(record)); } catch { /* storage unavailable */ }
    if (meta) meta.textContent = `Accepted on this device: ${new Date(record.accepted_at).toLocaleString()}`;
    closeDialog(backdrop);
    document.getElementById('main-content')?.focus();
  });

  document.querySelectorAll('[data-open-disclosure]').forEach((button) => {
    button.addEventListener('click', () => {
      closeMobileDrawer();
      window.requestAnimationFrame(() => openDialog(backdrop, {
        initialFocus: accept,
        closeOnEscape: true,
        onRequestClose: () => closeDialog(backdrop),
      }));
    });
  });
}

function initConfirmations() {
  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });
}

function initNavigation() {
  const path = window.location.pathname;
  document.querySelectorAll('[data-nav-path]').forEach((link) => {
    const navPath = link.dataset.navPath;
    const active = navPath === '/' ? path === '/' : path.startsWith(navPath);
    link.classList.toggle('is-active', active);
    if (active) link.setAttribute('aria-current', 'page');
  });

  const header = document.querySelector('.app-header');
  let compact = false;
  const syncHeader = () => {
    const next = window.scrollY > 48;
    if (next === compact) return;
    compact = next;
    header?.classList.toggle('is-compact', compact);
  };
  document.addEventListener('scroll', syncHeader, { passive: true });

  const drawer = document.getElementById('mobileDrawer');
  const toggle = document.getElementById('navToggle');
  if (!drawer || !toggle) return;
  const close = closeMobileDrawer;
  toggle.addEventListener('click', () => {
    drawer.inert = false;
    toggle.setAttribute('aria-expanded', 'true');
    openDialog(drawer, {
      initialFocus: drawer.querySelector('a[aria-current="page"], a'),
      onRequestClose: close,
    });
  });
  drawer.querySelectorAll('[data-close-drawer], a').forEach((element) => element.addEventListener('click', close));
}

function initConnectivity() {
  const banner = document.getElementById('connectionBanner');
  const text = document.getElementById('connectionBannerText');
  const sync = ({ state = navigator.onLine ? 'ready' : 'offline', queued = 0 } = {}) => {
    const degraded = state === 'offline' || state === 'connecting' || !navigator.onLine;
    if (banner) banner.hidden = !degraded;
    if (text && degraded) {
      text.textContent = !navigator.onLine
        ? `This device is offline. ${queued ? `${queued} scan request${queued === 1 ? '' : 's'} will remain queued. ` : ''}Existing results and exports remain available.`
        : `The diagnostic uplink is reconnecting. ${queued ? `${queued} request${queued === 1 ? '' : 's'} queued. ` : ''}Existing results remain available.`;
    }
    document.body.classList.toggle('is-degraded', degraded);
  };
  window.addEventListener('console:connection', (event) => sync(event.detail));
  window.addEventListener('console:queue', (event) => sync({ state: event.detail.connection, queued: event.detail.queued }));
  window.addEventListener('online', () => sync({ state: 'connecting' }));
  window.addEventListener('offline', () => sync({ state: 'offline' }));
  window.addEventListener('console:session-expired', () => {
    if (banner) banner.hidden = false;
    if (text) text.innerHTML = 'Your configuration session expired. Scan results are retained. <a href="/login?next=%2Fconfig">Sign in again</a> when ready.';
  });
  window.addEventListener('console:rate-limited', (event) => {
    const seconds = event.detail?.retryAfter;
    toast(seconds ? `Request limit reached. Try again in ${seconds} seconds.` : 'Request limit reached. Please wait, then try again.');
  });
  sync();
}

function initAccessibility() {
  const dialog = document.getElementById('accessibilityBackdrop');
  if (!dialog) return;
  const close = () => closeDialog(dialog);
  document.querySelectorAll('[data-open-accessibility]').forEach((button) => button.addEventListener('click', () => {
    closeMobileDrawer();
    window.requestAnimationFrame(() => openDialog(dialog, { initialFocus: dialog.querySelector('[data-close-accessibility]'), onRequestClose: close }));
  }));
  dialog.querySelector('[data-close-accessibility]')?.addEventListener('click', close);
}

function initPrivacy() {
  const screenshot = document.getElementById('screenshotMode');
  screenshot?.addEventListener('click', () => {
    const enabled = !document.body.classList.contains('screenshot-mode');
    document.body.classList.toggle('screenshot-mode', enabled);
    screenshot.setAttribute('aria-pressed', String(enabled));
    screenshot.textContent = `Screenshot privacy: ${enabled ? 'on' : 'off'}`;
    toast(enabled ? 'Private values masked' : 'Private values visible');
  });

  const notifications = document.getElementById('notificationToggle');
  if (!notifications) return;
  let enabled = false;
  try { enabled = window.localStorage.getItem(NOTIFICATION_KEY) === 'true'; } catch { /* unavailable */ }
  const render = () => {
    const granted = 'Notification' in window && Notification.permission === 'granted';
    enabled = enabled && granted;
    notifications.setAttribute('aria-pressed', String(enabled));
    notifications.textContent = `Scan notifications: ${enabled ? 'on' : 'off'}`;
  };
  notifications.addEventListener('click', async () => {
    if (!('Notification' in window)) {
      announce('This browser does not support system notifications.');
      return;
    }
    if (!enabled) enabled = (await Notification.requestPermission()) === 'granted';
    else enabled = false;
    try { window.localStorage.setItem(NOTIFICATION_KEY, String(enabled)); } catch { /* unavailable */ }
    render();
  });
  render();
}

function initStorageCheck() {
  try {
    const key = '__whois_storage_check__';
    window.localStorage.setItem(key, '1');
    window.localStorage.removeItem(key);
  } catch {
    toast('Device storage is unavailable; preferences will reset after this page closes.');
  }
}

initDisclosure();
initConfirmations();
initNavigation();
initConnectivity();
initAccessibility();
initPrivacy();
initStorageCheck();
