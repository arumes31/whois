const form = document.getElementById('loginForm');
const password = document.getElementById('password');
const toggle = document.getElementById('passwordToggle');
const caps = document.getElementById('capsLockStatus');
const submit = document.getElementById('loginSubmit');

toggle?.addEventListener('click', () => {
  const show = password.type === 'password';
  password.type = show ? 'text' : 'password';
  toggle.setAttribute('aria-pressed', String(show));
  toggle.textContent = show ? 'Hide' : 'Show';
  password.focus();
});

password?.addEventListener('keyup', (event) => {
  caps.textContent = event.getModifierState?.('CapsLock') ? 'Caps Lock is on.' : '';
});

form?.addEventListener('submit', () => {
  try { window.sessionStorage.setItem('whois_login_attempted_at', new Date().toISOString()); } catch { /* unavailable */ }
  submit.disabled = true;
  submit.setAttribute('aria-busy', 'true');
  submit.querySelector('span').textContent = 'AUTHENTICATING…';
});

document.querySelector('.alert-err')?.focus();
