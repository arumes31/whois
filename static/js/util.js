// Small shared helpers — no framework, no dependencies.

export function escapeHTML(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function timeStamp(date = new Date()) {
  return date.toLocaleTimeString(undefined, { hour12: false });
}

export function announce(message) {
  const region = document.getElementById('scanAnnouncement');
  if (!region) return;
  region.textContent = '';
  window.setTimeout(() => { region.textContent = message; }, 20);
}

export function splitTargets(value) {
  const seen = new Set();
  return String(value || '')
    .split(/[,\r\n]+/)
    .map((target) => target.trim())
    .filter((target) => {
      const identity = canonicalTargetIdentity(target);
      if (!target || seen.has(identity)) return false;
      seen.add(identity);
      return true;
    });
}

function parseIPv4(value) {
  const parts = String(value).split('.');
  if (parts.length !== 4) return null;
  const octets = [];
  for (const part of parts) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    octets.push(octet);
  }
  return octets;
}

function ipv4String(octets) {
  return octets.join('.');
}

function parseIPv6(value) {
  let input = String(value).toLowerCase();
  if (!input || input.includes('%')) return null;
  const compression = input.indexOf('::');
  if (compression !== input.lastIndexOf('::')) return null;

  const compressed = compression >= 0;
  const leftRaw = compressed ? input.slice(0, compression) : input;
  const rightRaw = compressed ? input.slice(compression + 2) : '';
  const leftTokens = leftRaw ? leftRaw.split(':') : [];
  const rightTokens = rightRaw ? rightRaw.split(':') : [];
  if (leftTokens.some((token) => !token) || rightTokens.some((token) => !token)) return null;

  const parseTokens = (tokens, allowIPv4) => {
    const words = [];
    for (let index = 0; index < tokens.length; index += 1) {
      const token = tokens[index];
      if (token.includes('.')) {
        if (!allowIPv4 || index !== tokens.length - 1) return null;
        const octets = parseIPv4(token);
        if (!octets) return null;
        words.push((octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(token)) return null;
        words.push(Number.parseInt(token, 16));
      }
    }
    return words;
  };

  // An embedded dotted IPv4 address consumes the final 32 bits. It cannot
  // appear before a compression marker such as the invalid 192.0.2.1:: form.
  const leftWords = parseTokens(leftTokens, !compressed && rightTokens.length === 0);
  const rightWords = parseTokens(rightTokens, true);
  if (!leftWords || !rightWords) return null;
  const explicitCount = leftWords.length + rightWords.length;
  if (!compressed) return explicitCount === 8 ? leftWords : null;
  const omitted = 8 - explicitCount;
  if (omitted < 1) return null;
  return [...leftWords, ...new Array(omitted).fill(0), ...rightWords];
}

function isMappedIPv6(words) {
  return words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff;
}

function mappedIPv4(words) {
  return [words[6] >>> 8, words[6] & 0xff, words[7] >>> 8, words[7] & 0xff];
}

function ipv6String(words) {
  if (isMappedIPv6(words)) return `::ffff:${ipv4String(mappedIPv4(words))}`;
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < words.length;) {
    if (words[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < words.length && words[end] === 0) end += 1;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  if (bestLength < 2) return words.map((word) => word.toString(16)).join(':');
  const before = words.slice(0, bestStart).map((word) => word.toString(16)).join(':');
  const after = words.slice(bestStart + bestLength).map((word) => word.toString(16)).join(':');
  if (before && after) return `${before}::${after}`;
  if (before) return `${before}::`;
  return after ? `::${after}` : '::';
}

function canonicalIPAddress(value, { allowBrackets = true, allowTrailingRoot = true } = {}) {
  let candidate = String(value);
  if (candidate.includes('[') || candidate.includes(']')) {
    if (!allowBrackets || !candidate.startsWith('[') || !candidate.endsWith(']')
      || candidate.slice(1, -1).includes('[') || candidate.slice(1, -1).includes(']')) return null;
    candidate = candidate.slice(1, -1);
  } else if (candidate.endsWith('.')) {
    if (!allowTrailingRoot) return null;
    candidate = candidate.slice(0, -1);
  }

  const ipv4 = parseIPv4(candidate);
  if (ipv4) return { family: 4, value: ipv4String(ipv4) };

  let address = candidate;
  let zone = '';
  const zoneIndex = candidate.indexOf('%');
  if (zoneIndex >= 0) {
    address = candidate.slice(0, zoneIndex);
    zone = candidate.slice(zoneIndex + 1);
    if (!zone) return null;
  }
  const ipv6 = parseIPv6(address);
  if (!ipv6) return null;
  if (isMappedIPv6(ipv6)) return { family: 4, value: ipv4String(mappedIPv4(ipv6)) };
  return { family: 6, value: `${ipv6String(ipv6)}${zone ? `%${zone}` : ''}` };
}

function canonicalIPPrefix(value) {
  const input = String(value);
  const slash = input.lastIndexOf('/');
  const bits = input.slice(slash + 1);
  if (slash <= 0 || !/^(?:0|[1-9][0-9]*)$/.test(bits)) return null;
  const address = input.slice(0, slash);
  if (address.includes('[') || address.includes(']') || address.includes('%') || address.endsWith('.')) return null;
  const prefixLength = Number(bits);
  const ipv4 = parseIPv4(address);
  if (ipv4) {
    if (prefixLength > 32) return null;
    const numeric = (((ipv4[0] * 256 + ipv4[1]) * 256 + ipv4[2]) * 256 + ipv4[3]) >>> 0;
    const mask = prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0;
    const network = (numeric & mask) >>> 0;
    const masked = [network >>> 24, (network >>> 16) & 0xff, (network >>> 8) & 0xff, network & 0xff];
    return `${ipv4String(masked)}/${prefixLength}`;
  }

  const ipv6 = parseIPv6(address);
  if (!ipv6 || prefixLength > 128) return null;
  const fullWords = Math.floor(prefixLength / 16);
  const remainingBits = prefixLength % 16;
  const masked = ipv6.map((word, index) => {
    if (index < fullWords) return word;
    if (index > fullWords || remainingBits === 0) return 0;
    return word & ((0xffff << (16 - remainingBits)) & 0xffff);
  });
  return `${ipv6String(masked)}/${prefixLength}`;
}

function canonicalHostname(value) {
  let host = String(value);
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (!host || host.length > 253 || !host.includes('.')) return null;
  const labels = host.split('.');
  for (const label of labels) {
    if (!label || label.length > 63 || label.startsWith('-') || label.endsWith('-')
      || !/^[A-Za-z0-9-]+$/.test(label)) return null;
  }
  return host.toLowerCase();
}

function parseExplicitPort(value) {
  if (!/^[0-9]+$/.test(value)) return null;
  const numeric = Number(value);
  if (!Number.isSafeInteger(numeric) || numeric <= 0 || numeric > 65535) return null;
  return value;
}

function targetAuthority(raw) {
  let scheme = '';
  let remainder = raw;
  let urlLike = false;

  if (raw.startsWith('//')) {
    scheme = 'http';
    remainder = raw.slice(2);
    urlLike = true;
  } else {
    const schemeMatch = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(raw);
    if (schemeMatch) {
      scheme = schemeMatch[1].toLowerCase();
      if (scheme !== 'http' && scheme !== 'https') return null;
      remainder = raw.slice(schemeMatch[0].length);
      urlLike = true;
    } else if (raw.includes('://')) {
      return null;
    } else if (/[/?#]/.test(raw)) {
      scheme = 'http';
      urlLike = true;
    }
  }

  const boundary = remainder.search(/[/?#]/);
  const authority = boundary >= 0 ? remainder.slice(0, boundary) : remainder;
  if (!authority || authority.includes('@') || (urlLike && authority.includes('%'))) return null;

  let host = authority;
  let port = '';
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close <= 1 || authority.indexOf(']', close + 1) >= 0) return null;
    host = authority.slice(1, close);
    const suffix = authority.slice(close + 1);
    if (suffix) {
      if (!suffix.startsWith(':') || suffix.length === 1) return null;
      port = parseExplicitPort(suffix.slice(1));
      if (port === null) return null;
    }
  } else {
    const colonCount = (authority.match(/:/g) || []).length;
    if (colonCount > 1) return null;
    if (colonCount === 1) {
      const split = authority.lastIndexOf(':');
      host = authority.slice(0, split);
      if (!host) return null;
      port = parseExplicitPort(authority.slice(split + 1));
      if (port === null) return null;
    }
  }

  const address = canonicalIPAddress(host, { allowBrackets: false, allowTrailingRoot: true });
  const canonicalHost = address?.value || canonicalHostname(host);
  if (!canonicalHost) return null;
  const normalized = port && address?.family === 6
    ? `[${canonicalHost}]:${port}`
    : `${canonicalHost}${port ? `:${port}` : ''}`;
  return `${scheme}|${normalized}`;
}

// Mirror the server's host-oriented identity closely enough to keep aliases
// from starting indistinguishable concurrent scans. Paths and query strings do
// not affect diagnostics; scheme, host, and an explicit non-default port do.
export function canonicalTargetIdentity(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';

  const asn = /^as0*([0-9]+)$/i.exec(raw);
  if (asn) {
    const number = BigInt(asn[1]);
    if (number > 0n && number <= 0xffffffffn) return `asn|AS${number}`;
  }

  const prefix = canonicalIPPrefix(raw);
  if (prefix) return `prefix|${prefix}`;
  const address = canonicalIPAddress(raw);
  if (address) return `|${address.value}`;

  return targetAuthority(raw) || `invalid|${raw}`;
}

export function createRequestID() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  const random = Math.random().toString(36).slice(2, 14);
  return `scan-${Date.now().toString(36)}-${random}`;
}

function readCookie(name) {
  const prefix = `${encodeURIComponent(name)}=`;
  const item = document.cookie.split(';').map((part) => part.trim())
    .find((part) => part.startsWith(prefix));
  return item ? decodeURIComponent(item.slice(prefix.length)) : '';
}

export function csrfToken() {
  return document.querySelector('meta[name="csrf-token"]')?.content
    || document.body?.dataset.csrfToken
    || document.querySelector('input[name="_csrf"]')?.value
    || readCookie('_csrf')
    || readCookie('csrf')
    || '';
}

export async function fetchWithCSRF(input, init = {}) {
  const options = { credentials: 'same-origin', ...init };
  const method = String(options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const token = csrfToken();
    if (token && !headers.has('X-CSRF-Token')) headers.set('X-CSRF-Token', token);
  }
  options.headers = headers;
  const response = await window.fetch(input, options);
  if (response.status === 401) {
    window.dispatchEvent(new CustomEvent('console:session-expired', { detail: { input: String(input) } }));
  } else if (response.status === 429) {
    const header = response.headers.get('retry-after');
    const numericDelay = header !== null && header.trim() !== '' ? Number(header) : NaN;
    const retryAfter = Number.isFinite(numericDelay) && numericDelay >= 0
      ? numericDelay
      : Math.max(0, Math.ceil((Date.parse(header || '') - Date.now()) / 1000) || 0);
    window.dispatchEvent(new CustomEvent('console:rate-limited', {
      detail: { retryAfter },
    }));
  }
  return response;
}

function responseMessage(payload, fallback) {
  if (payload && typeof payload === 'object') {
    return String(payload.error || payload.message || payload.detail || fallback);
  }
  const text = String(payload || '').trim();
  if (!text) return fallback;
  if (/<[a-z][\s\S]*>/i.test(text)) {
    const parsed = new DOMParser().parseFromString(text, 'text/html');
    return parsed.querySelector('[role="alert"], .alert-err, main')?.textContent?.trim()
      || parsed.body.textContent.trim()
      || fallback;
  }
  return text;
}

export async function readResponse(response, { json = false } = {}) {
  const type = response.headers.get('content-type') || '';
  let payload;
  if (json || type.includes('application/json')) {
    try { payload = await response.json(); } catch { payload = null; }
  } else {
    payload = await response.text();
  }
  if (!response.ok) {
    const requestID = response.headers.get('x-request-id');
    const fallbackCode = globalThis.crypto?.randomUUID?.().slice(0, 8).toUpperCase() || String(Date.now()).slice(-8);
    const code = String(requestID || fallbackCode).replace(/[^A-Za-z0-9._:-]/g, '').slice(0, 32);
    const base = response.status === 403
      ? 'The request was refused. Refresh the page to renew its security token, then try again.'
      : responseMessage(payload, `Request failed (${response.status})`);
    const error = new Error(`${base} Reference: ${code}`);
    error.code = code;
    error.status = response.status;
    throw error;
  }
  if (json && (!payload || typeof payload !== 'object')) {
    throw new Error('The server returned an invalid response.');
  }
  return payload;
}

let toastTimer;
export function toast(message = 'Copied to clipboard') {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = message;
  el.classList.add('is-show');
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => el.classList.remove('is-show'), 1800);
}

export function copyText(text, feedback = 'Copied to clipboard') {
  if (!text) return;
  const onSuccess = () => toast(feedback);
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(onSuccess).catch(() => fallbackCopy(text, onSuccess));
  } else {
    fallbackCopy(text, onSuccess);
  }
}

export function fallbackCopy(text, onSuccess) {
  try {
    const area = document.createElement('textarea');
    area.value = text;
    area.style.position = 'fixed';
    area.style.left = '-9999px';
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(area);
    if (ok && onSuccess) onSuccess();
  } catch (err) {
    console.error('Fallback copy failed:', err);
  }
}

// Give every copyable record a real button instead of assigning button semantics
// to arbitrary elements such as <dd>, <pre>, and <li>.
export function wireCopyable(root) {
  root.querySelectorAll('.clickable-record:not([data-copy-wired])').forEach((el) => {
    el.dataset.copyWired = '1';
    el.removeAttribute('role');
    el.removeAttribute('tabindex');
    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'copy-trigger';
    trigger.setAttribute('aria-label', 'Copy value');
    trigger.title = 'Copy value';
    trigger.textContent = 'COPY';
    const run = () => {
      const clone = el.cloneNode(true);
      clone.querySelectorAll('.copy-trigger').forEach((button) => button.remove());
      let text = clone.textContent.trim();
      const strong = el.querySelector('strong, dt');
      if (strong) {
        text = text.replace(strong.innerText, '').trim();
        if (text.startsWith(':')) text = text.substring(1).trim();
      }
      copyText(text);
      el.classList.add('record-copied');
      window.setTimeout(() => el.classList.remove('record-copied'), 900);
    };
    trigger.addEventListener('click', (event) => {
      event.stopPropagation();
      run();
    });
    el.appendChild(trigger);
  });
}

const dialogStates = new WeakMap();

function focusableElements(dialog) {
  return [...dialog.querySelectorAll(
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), details > summary, [tabindex]:not([tabindex="-1"])',
  )].filter((element) => element.getClientRects().length > 0 && !element.closest('[inert]'));
}

export function openDialog(dialog, {
  initialFocus,
  closeOnEscape = true,
  onRequestClose,
} = {}) {
  if (!dialog || dialogStates.has(dialog)) return;
  const returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const inerted = [...document.body.children]
    .filter((element) => element instanceof HTMLElement
      && element !== dialog
      && !element.matches('script, .crt-scanlines, .crt-vignette, #toast'))
    .map((element) => ({ element, inert: element.inert }));
  inerted.forEach(({ element }) => { element.inert = true; });

  const requestClose = () => {
    if (typeof onRequestClose === 'function') onRequestClose();
    else closeDialog(dialog);
  };
  const onKeyDown = (event) => {
    if (event.key === 'Escape' && closeOnEscape) {
      event.preventDefault();
      requestClose();
      return;
    }
    if (event.key !== 'Tab') return;
    const focusable = focusableElements(dialog);
    if (focusable.length === 0) {
      event.preventDefault();
      dialog.focus();
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    } else if (!dialog.contains(document.activeElement)) {
      event.preventDefault();
      first.focus();
    }
  };

  dialogStates.set(dialog, { inerted, onKeyDown, returnFocus });
  dialog.classList.add('is-open');
  dialog.removeAttribute('aria-hidden');
  document.body.classList.add('modal-open');
  document.addEventListener('keydown', onKeyDown, true);
  window.requestAnimationFrame(() => {
    if (!dialogStates.has(dialog) || !dialog.classList.contains('is-open')) return;
    const preferred = typeof initialFocus === 'string'
      ? dialog.querySelector(initialFocus)
      : initialFocus;
    (preferred || focusableElements(dialog)[0] || dialog).focus();
  });
}

export function closeDialog(dialog, { restoreFocus = true } = {}) {
  const state = dialogStates.get(dialog);
  if (!dialog || !state) return;
  document.removeEventListener('keydown', state.onKeyDown, true);
  state.inerted.forEach(({ element, inert }) => { element.inert = inert; });
  dialogStates.delete(dialog);
  dialog.classList.remove('is-open');
  dialog.setAttribute('aria-hidden', 'true');
  document.body.classList.remove('modal-open');
  if (restoreFocus && state.returnFocus?.isConnected && !state.returnFocus.inert) {
    state.returnFocus.focus();
  }
}

export function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

export function resultHasError(data) {
  if (typeof data === 'string') return /^(?:whois\s+)?error:/i.test(data.trim());
  return isPlainObject(data) && Boolean(data.error);
}

// Deterministic per-target accent: all hues live inside the phosphor band.
const palette = ['#00f48e', '#00ff3c', '#5cffb1', '#a8ffd6', '#00c46f', '#7dffc4', '#2eea9d', '#c9ffe6'];
const colorAssignments = new Map();
let paletteCursor = 0;

export function targetColor(target) {
  if (!colorAssignments.has(target)) {
    colorAssignments.set(target, palette[paletteCursor % palette.length]);
    paletteCursor += 1;
  }
  return colorAssignments.get(target);
}

export function resetColors() {
  colorAssignments.clear();
  paletteCursor = 0;
}

export function downloadBlob(content, mime, filename) {
  const blob = new Blob([content], { type: mime });
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.setTimeout(() => window.URL.revokeObjectURL(url), 0);
}
