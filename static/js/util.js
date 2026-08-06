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

// Wire every .clickable-record inside `root` to copy its own text.
export function wireCopyable(root) {
  root.querySelectorAll('.clickable-record:not([data-copy-wired])').forEach((el) => {
    el.dataset.copyWired = '1';
    el.setAttribute('role', 'button');
    el.setAttribute('tabindex', '0');
    el.setAttribute('title', 'Copy value');
    const run = () => {
      let text = el.innerText.trim();
      const strong = el.querySelector('strong, dt');
      if (strong) {
        text = text.replace(strong.innerText, '').trim();
        if (text.startsWith(':')) text = text.substring(1).trim();
      }
      copyText(text);
      el.classList.add('record-copied');
      window.setTimeout(() => el.classList.remove('record-copied'), 900);
    };
    el.addEventListener('click', run);
    el.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        run();
      }
    });
  });
}

export function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

export function resultHasError(data) {
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
