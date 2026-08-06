// Per-service renderers: streamed payloads -> phosphor readout markup.
import { escapeHTML, resultHasError } from './util.js';

const SERVICE_LABELS = {
  target: 'TARGET PROFILE',
  geo: 'GEO LOCATION',
  whois: 'WHOIS DATA',
  dns: 'DNS RECORDS',
  subdomains: 'SUBDOMAIN DISCOVERY',
  portscan: 'PORT SCAN',
  ping: 'PING ICMP',
  route: 'TRACEROUTE',
  trace: 'DNS TRACE',
  ssl: 'SSL/TLS',
  http: 'HTTP INSPECTOR',
  ct: 'CT SUBDOMAINS',
};

export function serviceLabel(service) {
  return SERVICE_LABELS[service] || String(service).replace(/_/g, ' ').toUpperCase();
}

function statusDot(status) {
  return `<span class="status-dot" data-status="${status}"></span>`;
}

function openDetails(service, status, body, { open = true } = {}) {
  const isOpen = open || status === 'error' || service === 'target';
  return `<details${isOpen ? ' open' : ''}><summary>${statusDot(status)}${serviceLabel(service)}</summary><div class="service-section__body">${body}</div></details>`;
}

function errorDetails(service, message) {
  return openDetails(service, 'error', `<div class="findings findings--err"><strong>MODULE FAULT</strong>${escapeHTML(message)}</div>`);
}

function kvRow(label, value, { copy = true, hot = false } = {}) {
  const cls = copy ? `clickable-record${hot ? ' clickable-record--hot' : ''}` : '';
  return `<dl class="kv"><dt>${escapeHTML(label)}</dt><dd class="${cls}">${escapeHTML(value ?? 'unknown')}</dd></dl>`;
}

function rawBlock(content) {
  return `<details><summary><small>RAW DATA</small></summary><pre class="raw-block clickable-record">${escapeHTML(content)}</pre></details>`;
}

function preLines(lines, extraClass = '') {
  return `<pre class="raw-block clickable-record ${extraClass}">${escapeHTML(lines.join('\n'))}</pre>`;
}

/* ---------- individual services ---------- */

function renderTarget(data) {
  const ips = Array.isArray(data.ips) ? data.ips : [];
  const ipBlocks = ips.map((ip) => {
    const flags = [
      ip.is_bogon ? 'BOGON' : '',
      ip.is_cgnat ? 'CGNAT' : '',
      ip.is_documentation ? 'DOC-RANGE' : '',
      ip.is_private ? 'PRIVATE' : '',
    ].filter(Boolean);
    return `<div style="margin-bottom:10px">
      <div><span class="chip">IPv${escapeHTML(ip.version)}</span>
      <span class="clickable-record clickable-record--hot"> ${escapeHTML(ip.address)}</span></div>
      <div style="color:var(--phos-50);font-size:10px">SCOPE: ${escapeHTML(ip.scope)}${flags.length ? ` · ${flags.join(' · ')}` : ''}</div>
      ${ip.reverse_dns?.length ? `<div style="color:var(--phos-50);font-size:10px">PTR: ${escapeHTML(ip.reverse_dns.join(', '))}</div>` : ''}
    </div>`;
  }).join('');
  const warnings = (data.warnings || [])
    .map((w) => `<div style="color:var(--amber);font-size:11px">⚠ ${escapeHTML(w)}</div>`).join('');
  const body = `
    <dl class="kv"><dt>NORMALIZED</dt><dd class="clickable-record clickable-record--hot">${escapeHTML(data.normalized || data.input)}</dd></dl>
    ${data.resolution_ms ? kvRow('SYSTEM DNS', `${data.resolution_ms} ms`) : ''}
    ${data.prefix ? kvRow('PREFIX', data.prefix) : ''}
    ${data.kind ? kvRow('KIND', data.kind) : ''}
    ${ipBlocks}${warnings}
    ${data.error ? `<div class="findings findings--err">${escapeHTML(data.error)}</div>` : ''}`;
  return openDetails('target', data.valid ? 'success' : 'error', body, { open: true });
}

function renderGeo(data) {
  if (!data || data.error) {
    return openDetails('geo', 'error', `<div style="color:var(--phos-50)">Geo data unavailable — install a local GeoLite2 City database to enable this module.</div>`);
  }
  const body = `
    ${kvRow('LOCATION', `${data.city || 'Unknown city'}, ${data.country || ''}`)}
    ${kvRow('IP ADDRESS', data.query)}
    ${data.timezone ? kvRow('TIMEZONE', data.timezone) : ''}
    ${kvRow('COORDINATES', `${data.lat}, ${data.lon}`)}`;
  return openDetails('geo', 'success', body);
}

function renderWhois(data) {
  if (typeof data === 'string' && /^(?:whois\s+)?error:/i.test(data.trim())) {
    return errorDetails('whois', data);
  }
  if (data && typeof data === 'object' && data.error) {
    return errorDetails('whois', data.error);
  }
  if (data && typeof data === 'object') {
    const body = `
      ${kvRow('REGISTRAR', data.registrar || 'Unknown')}
      ${kvRow('CREATED', data.created || 'Unknown')}
      ${kvRow('EXPIRES', data.expiry || 'Unknown', { hot: true })}
      ${data.raw ? rawBlock(data.raw) : ''}`;
    return openDetails('whois', 'success', body, { open: true });
  }
  if (data) {
    return openDetails('whois', 'success', preLines([String(data)]));
  }
  return openDetails('whois', 'error', `<div style="color:var(--phos-50)">No WHOIS data returned.</div>`);
}

function renderDns(data) {
  if (data && data.error) return errorDetails('dns', data.error);
  if (data && Object.keys(data).length > 0) {
    let inner = '';
    for (const [type, val] of Object.entries(data)) {
      inner += `<div class="dns-type">${escapeHTML(type)}</div><div class="dns-values">`;
      if (Array.isArray(val)) {
        val.forEach((v) => { inner += `<div class="clickable-record">${escapeHTML(v)}</div>`; });
      } else if (type === 'Subdomains') {
        inner += `<div style="color:var(--phos-50)">Found ${Object.keys(val).length} prefixes</div>`;
      } else {
        inner += `<div class="clickable-record">${escapeHTML(JSON.stringify(val))}</div>`;
      }
      inner += '</div>';
    }
    return openDetails('dns', 'success', inner, { open: true });
  }
  return openDetails('dns', 'success', `<div style="color:var(--phos-50)">No records found.</div>`);
}

function renderSubdomains(data) {
  if (data && typeof data === 'object' && data.error) {
    return errorDetails('subdomains', data.error);
  }
  if (data && Object.keys(data).length > 0) {
    let inner = '';
    for (const [fqdn, records] of Object.entries(data)) {
      inner += `<div style="margin-bottom:10px;border-bottom:1px dashed var(--line);padding-bottom:6px">
        <div class="clickable-record clickable-record--hot" style="font-weight:600">${escapeHTML(fqdn)}</div>`;
      for (const [type, vals] of Object.entries(records || {})) {
        const list = Array.isArray(vals) ? vals.join(', ') : String(vals);
        inner += `<div style="font-size:11px;color:var(--phos-70)"><span style="color:var(--phos-bright)">${escapeHTML(type)}</span> ▸ <span class="clickable-record">${escapeHTML(list)}</span></div>`;
      }
      inner += '</div>';
    }
    return openDetails('subdomains', 'success', inner, { open: true });
  }
  return openDetails('subdomains', 'success', `<div style="color:var(--phos-50)">No common subdomains found.</div>`);
}

function renderPortscan(data) {
  const open = data && typeof data === 'object' && !Array.isArray(data) ? (data.open || {}) : {};
  const rawErrors = data && typeof data === 'object'
    ? data.error
    : (typeof data === 'string' && resultHasError(data) ? data : []);
  const errors = Array.isArray(rawErrors) ? rawErrors : (rawErrors ? [String(rawErrors)] : []);
  let status = 'success';
  let inner = '';
  const entries = Object.entries(open);
  if (entries.length) {
    inner += entries
      .sort((a, b) => Number(a[0]) - Number(b[0]))
      .map(([port, banner]) => `<dl class="kv"><dt>PORT ${escapeHTML(port)}</dt><dd class="clickable-record clickable-record--hot">OPEN${banner ? ` — ${escapeHTML(banner)}` : ''}</dd></dl>`)
      .join('');
  } else {
    inner += `<div style="color:var(--phos-50)">No open ports detected in the selected range.</div>`;
  }
  if (errors.length) {
    status = 'error';
    inner += `<div class="findings findings--err"><strong>SCAN FAULT</strong>${escapeHTML(errors.join('; '))}</div>`;
  }
  return openDetails('portscan', status, inner);
}

function renderPing(data, target, section) {
  const lines = Array.isArray(data) ? data : (Array.isArray(data?.lines) ? data.lines : []);
  const failed = resultHasError(data);
  const errorMessage = typeof data === 'string' ? data : data?.error;
  const rtts = [];
  lines.forEach((line) => {
    const match = /time[=<]([\d.]+)\s*ms/i.exec(line);
    if (match) rtts.push(Number(match[1]));
  });
  const chartId = `ping-${Math.random().toString(36).slice(2, 10)}`;
  const chartHtml = rtts.length
    ? `<div class="ping-chart"><canvas id="${chartId}" aria-label="Ping RTT chart"></canvas></div>` : '';
  const avg = rtts.length ? (rtts.reduce((a, b) => a + b, 0) / rtts.length).toFixed(1) : null;
  const body = `
    ${failed ? `<div class="findings findings--err">${escapeHTML(errorMessage || 'Ping failed.')}</div>` : ''}
    ${avg ? `<div class="chips"><span class="chip chip--ok">AVG ${avg} ms</span><span class="chip">N=${rtts.length}</span></div>` : ''}
    ${chartHtml}
    <div class="stream-lines">${lines.map((l) => `<div>${escapeHTML(l)}</div>`).join('')}</div>`;
  // chart wiring happens in cards.js after insertion
  section.dataset.chartId = chartId;
  section.dataset.chartRtts = JSON.stringify(rtts);
  return openDetails('ping', failed ? 'error' : 'success', body);
}

function renderRoute(data) {
  const lines = Array.isArray(data) ? data : (Array.isArray(data?.lines) ? data.lines : []);
  const failed = resultHasError(data);
  const errorMessage = typeof data === 'string' ? data : data?.error;
  const body = `${failed ? `<div class="findings findings--err">${escapeHTML(errorMessage || 'Traceroute failed.')}</div>` : ''}${preLines(lines)}`;
  return openDetails('route', failed ? 'error' : 'success', body);
}

function renderTrace(data) {
  const lines = Array.isArray(data) ? data : (Array.isArray(data?.lines) ? data.lines : []);
  const failed = resultHasError(data);
  const errorMessage = typeof data === 'string' ? data : data?.error;
  const body = `${failed ? `<div class="findings findings--err">${escapeHTML(errorMessage || 'DNS trace failed.')}</div>` : ''}${preLines(lines)}`;
  return openDetails('trace', failed ? 'error' : 'success', body);
}

function renderSsl(data) {
  if (data.error) return errorDetails('ssl', data.error);
  const score = Number(data.score);
  const failed = score < 60;
  const flags = [
    data.verified ? '<span class="chip chip--ok">TRUSTED CHAIN</span>' : '<span class="chip chip--bad">UNTRUSTED CHAIN</span>',
    data.hostname_valid ? '<span class="chip chip--ok">HOSTNAME VALID</span>' : '<span class="chip chip--bad">HOSTNAME MISMATCH</span>',
    data.self_signed ? '<span class="chip chip--bad">SELF-SIGNED</span>' : '',
    data.expired ? '<span class="chip chip--bad">EXPIRED</span>' : '',
    data.expiring_soon ? '<span class="chip chip--warn">EXPIRING SOON</span>' : '',
  ].filter(Boolean).join('');
  const issues = (data.issues || []).map((i) => `<li>${escapeHTML(i)}</li>`).join('');
  const body = `
    <div class="chips"><span class="chip chip--ok">${escapeHTML(data.protocol)}</span><span class="chip">${escapeHTML(data.cipher_suite)}</span>${flags}</div>
    ${kvRow('SUBJECT', data.subject || 'Unknown')}
    ${kvRow('ISSUER', data.issuer)}
    ${kvRow('EXPIRY', `${String(data.expiry || '').split('T')[0]} (${data.days_left} days)`, { hot: true })}
    ${kvRow('VERSIONS', (data.supported_versions || []).join(', '))}
    ${kvRow('OCSP / SCT / ALPN', `${data.ocsp_status || 'n/a'} · ${data.sct_count} · ${data.alpn || 'n/a'}`, { copy: false })}
    ${data.verification_error ? `<div class="findings findings--err"><strong>VERIFICATION ERROR</strong>${escapeHTML(data.verification_error)}</div>` : ''}
    ${issues ? `<div class="findings"><strong>ATTENTION NEEDED</strong><ul>${issues}</ul></div>` : '<div class="findings findings--ok"><strong>POSTURE</strong>No immediate TLS issues detected.</div>'}
    <details style="margin-top:8px"><summary><small>CERTIFICATE CHAIN &amp; SANS</small></summary><pre class="raw-block">${escapeHTML(JSON.stringify({ chain: data.chain, sans: data.sans }, null, 2))}</pre></details>
    ${data.pem ? `<details style="margin-top:6px"><summary><small>PEM CERTIFICATE</small></summary><pre class="raw-block">${escapeHTML(data.pem)}</pre></details>` : ''}`;
  return openDetails('ssl', failed ? 'error' : 'success', body);
}

function renderHttp(data) {
  if (data.error) return errorDetails('http', data.error);
  const score = Number(data.score);
  const failed = score < 60;
  let securityRows = '';
  for (const [header, val] of Object.entries(data.security || {})) {
    const isSet = val !== 'Not Set';
    securityRows += `<dl class="kv"><dt>${escapeHTML(header)}</dt><dd><span class="chip ${isSet ? 'chip--ok' : 'chip--bad'}">${isSet ? 'SET' : 'MISSING'}</span>${isSet ? ` <span class="clickable-record">${escapeHTML(val)}</span>` : ''}</dd></dl>`;
  }
  const issues = (data.issues || []).map((i) => `<li>${escapeHTML(i)}</li>`).join('');
  const redirects = (data.redirects || [])
    .map((r) => `<li><span class="chip">${escapeHTML(r.status)}</span> ${escapeHTML(r.url)} → ${escapeHTML(r.location || '')}</li>`).join('');
  const cookies = (data.cookies || [])
    .map((c) => `<li><strong>${escapeHTML(c.name)}</strong> · ${c.secure ? 'Secure' : 'not Secure'} · ${c.http_only ? 'HttpOnly' : 'no HttpOnly'} · SameSite=${escapeHTML(c.same_site || 'n/a')}</li>`).join('');
  const checks = (data.security_checks || []).map((check) => {
    const tone = check.status === 'pass' ? 'chip--ok' : (check.status === 'warning' ? 'chip--warn' : 'chip--bad');
    return `<li><span class="chip ${tone}">${escapeHTML(check.status)}</span> <strong>${escapeHTML(check.name)}</strong>${check.guidance ? ` — ${escapeHTML(check.guidance)}` : ''}</li>`;
  }).join('');
  const statusOk = String(data.status || '').startsWith('2');
  const body = `
    <div class="chips">
      <span class="chip ${statusOk ? 'chip--ok' : 'chip--warn'}">${escapeHTML(data.status || 'UNKNOWN')}</span>
      <span class="chip">${escapeHTML(data.protocol)}</span>
      <span class="chip">${escapeHTML(data.response_time_ms)} ms</span>
      ${data.server ? `<span class="chip">${escapeHTML(data.server)}</span>` : ''}
    </div>
    ${data.final_url ? kvRow('FINAL URL', data.final_url) : ''}
    ${kvRow('SCORE', `${data.score} ${data.grade ? `· ${data.grade}` : ''}`, { copy: false, hot: true })}
    ${securityRows}
    ${redirects ? `<div class="dns-type">REDIRECTS</div><ul style="padding:6px 8px;font-size:11px">${redirects}</ul>` : ''}
    ${cookies ? `<div class="dns-type">COOKIES</div><ul style="padding:6px 8px;font-size:11px">${cookies}</ul>` : ''}
    ${checks ? `<div class="dns-type">SECURITY CHECKS</div><ul style="padding:6px 8px;font-size:11px">${checks}</ul>` : ''}
    ${issues ? `<div class="findings"><strong>ATTENTION NEEDED</strong><ul>${issues}</ul></div>` : ''}`;
  return openDetails('http', failed ? 'error' : 'success', body);
}

function renderCt(data) {
  if (data && data.error) return errorDetails('ct', data.error);
  if (data && Object.keys(data).length > 0) {
    const items = Object.keys(data)
      .map((sub) => `<li class="clickable-record" style="padding:2px 0">▸ ${escapeHTML(sub)}</li>`).join('');
    return openDetails('ct', 'success', `<ul style="font-size:11px">${items}</ul>`);
  }
  return openDetails('ct', 'success', `<div style="color:var(--phos-50)">No subdomains found in CT logs.</div>`);
}

const RENDERERS = {
  target: renderTarget,
  geo: renderGeo,
  whois: renderWhois,
  dns: renderDns,
  subdomains: renderSubdomains,
  portscan: renderPortscan,
  ping: renderPing,
  route: renderRoute,
  trace: renderTrace,
  ssl: renderSsl,
  http: renderHttp,
  ct: renderCt,
};

export function renderService(service, data, target, section) {
  const renderer = RENDERERS[service];
  if (!renderer) {
    return openDetails(service, 'success', preLines([JSON.stringify(data, null, 2)]));
  }
  return renderer(data, target, section);
}

export function skeletonHtml() {
  return `<div class="skel" aria-hidden="true"><i style="width:88%"></i><i style="width:64%"></i><i style="width:76%"></i></div>`;
}

export function skippedDetails(service, reason = '') {
  const messages = {
    'profile-only': 'Skipped because this target is available for profile inspection only.',
    'invalid-target': 'Skipped because the target is invalid.',
    failed: 'No result was returned before the diagnostic request failed.',
    interrupted: 'No result was returned before the diagnostic stream was interrupted.',
  };
  const message = messages[reason] || 'No result was returned by this module.';
  return openDetails(service, 'skipped', `<div class="module-skipped">${message}</div>`, { open: Boolean(reason) });
}
