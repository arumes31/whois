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
  return Object.hasOwn(SERVICE_LABELS, service)
    ? SERVICE_LABELS[service] : String(service).replace(/_/g, ' ').toUpperCase();
}

function statusDot(status) {
  return `<span class="status-dot" data-status="${status}"></span>`;
}

function openDetails(service, status, body, { open = true } = {}) {
  const isOpen = open || status === 'error' || service === 'target';
  return `<details${isOpen ? ' open' : ''}><summary>${statusDot(status)}${escapeHTML(serviceLabel(service))}</summary><div class="service-section__body">${body}</div></details>`;
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

function queryButton(target, label = 'QUERY') {
  return `<button type="button" class="inline-action" data-query-target="${escapeHTML(target)}" aria-label="Run diagnostics for ${escapeHTML(target)}">${label}</button>`;
}

function spfRecord(record) {
  const parts = String(record).trim().split(/\s+/);
  const mechanisms = parts.slice(1).map((part) => {
    const qualifier = /^[+?~-]/.test(part) ? part[0] : '+';
    const value = /^[+?~-]/.test(part) ? part.slice(1) : part;
    const tone = qualifier === '-' ? 'chip--ok' : (qualifier === '~' || qualifier === '?' ? 'chip--warn' : '');
    return `<span class="chip ${tone}" title="SPF qualifier ${escapeHTML(qualifier)}">${escapeHTML(value)}</span>`;
  }).join('');
  return `<div class="dns-policy"><strong>SPF POLICY</strong><div class="chips">${mechanisms}</div><code>${escapeHTML(record)}</code></div>`;
}

function dmarcRecord(record) {
  const policy = /(?:^|;)\s*p\s*=\s*([^;\s]+)/i.exec(record)?.[1]?.toLowerCase() || 'none';
  const percent = Number(/(?:^|;)\s*pct\s*=\s*(\d+)/i.exec(record)?.[1] || 100);
  const strong = ['reject', 'quarantine'].includes(policy) && percent === 100;
  const tone = strong ? 'chip--ok' : 'chip--warn';
  const label = strong ? 'ENFORCED' : 'MONITORING / PARTIAL';
  return `<div class="dns-policy"><strong>DMARC STRENGTH</strong><div class="chips"><span class="chip ${tone}">${label}</span><span class="chip">p=${escapeHTML(policy)}</span><span class="chip">pct=${percent}</span></div><code>${escapeHTML(record)}</code></div>`;
}

/* ---------- individual services ---------- */

function renderTarget(data) {
  const restriction = data.query_allowed === false && typeof data.query_restriction === 'string'
    ? data.query_restriction.trim() : '';
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
      ${ip.reverse_dns?.length ? `<div class="reverse-hosts">PTR: ${ip.reverse_dns.map((host) => `<span>${escapeHTML(host)} ${queryButton(host)}</span>`).join('')}</div>` : ''}
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
    ${restriction ? `<div class="findings findings--err"><strong>BLOCKED BY POLICY</strong>${escapeHTML(restriction)}</div>` : ''}
    ${data.error ? `<div class="findings findings--err">${escapeHTML(data.error)}</div>` : ''}`;
  return openDetails('target', data.valid && !restriction ? 'success' : 'error', body, { open: true });
}

function renderGeo(data) {
  if (!data || data.error) {
    return errorDetails('geo', data?.error || 'Geo data unavailable.');
  }
  const body = `
    ${kvRow('LOCATION', `${data.city || 'Unknown city'}, ${data.country || ''}`)}
    ${data.query && data.query !== data.ip ? kvRow('TARGET', data.query) : ''}
    ${data.ip ? kvRow('IP ADDRESS', data.ip) : ''}
    ${data.timezone ? kvRow('TIMEZONE', data.timezone) : ''}
    ${data.has_coordinates === true ? kvRow('COORDINATES', `${data.lat}, ${data.lon}`) : ''}
    <p class="result-note">Location is estimated from ${escapeHTML(data.source || 'the local database')}; it is not a device's precise location.</p>`;
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
    const network = data.network;
    const isNetwork = data.kind === 'ip' || Boolean(network);
    let body = `<h3 class="registration-title">${isNetwork ? 'IP network registration' : 'Domain registration'}</h3>`;
    if (data.source) {
      const source = String(data.source).toUpperCase();
      let sourceLink = '';
      try {
        const url = new URL(data.source_url);
        if (['http:', 'https:'].includes(url.protocol) && url.hostname && !url.username && !url.password) {
          sourceLink = ` · <a href="${escapeHTML(url.href)}" target="_blank" rel="noopener noreferrer" aria-label="Registry response (opens in a new tab)">Registry response</a>`;
        }
      } catch { /* A missing or invalid source URL has no link. */ }
      const queriedAt = data.queried_at && !Number.isNaN(Date.parse(data.queried_at))
        ? `<time datetime="${escapeHTML(data.queried_at)}">${escapeHTML(new Date(data.queried_at).toISOString().replace('T', ' ').replace('.000Z', ' UTC'))}</time>` : '';
      body += `<p class="registration-provenance">${escapeHTML(source)}${sourceLink}${queriedAt ? `<br>Retrieved ${queriedAt}` : ''}</p>`;
    }
    if (isNetwork) {
      for (const [label, value] of [
        ['NETWORK', network?.name], ['HANDLE', network?.handle || data.handle],
        ['ORGANIZATION', data.organization], ['FIRST ADDRESS', network?.start_address],
        ['LAST ADDRESS', network?.end_address], ['REGISTRY COUNTRY', network?.country],
        ['ADDRESS FAMILY', network?.ip_version], ['ALLOCATION TYPE', network?.type],
      ]) {
        if (value) body += kvRow(label, value);
      }
      if (network?.country) body += '<p class="result-note">Registry country describes the allocation, not the physical location of this IP.</p>';
    } else {
      if (data.query && data.domain && data.query.toLowerCase().replace(/\.$/, '') !== data.domain.toLowerCase().replace(/\.$/, '')) {
        body += kvRow('TARGET', data.query);
        body += '<p class="result-note">Registration belongs to the registered domain below; host diagnostics still use your original target.</p>';
      }
      if (data.domain) body += kvRow('DOMAIN', data.domain);
      body += kvRow('REGISTRAR', data.registrar || 'Not provided');
      body += kvRow('CREATED', data.created || 'Not provided');
      body += kvRow('EXPIRES', data.expiry || 'Not provided', { hot: true });
      if (data.organization) body += kvRow('REGISTRANT', data.organization);
      if (Array.isArray(data.nameservers) && data.nameservers.length) {
        body += kvRow('NAMESERVERS', data.nameservers.join('\n'));
      }
      if (typeof data.dnssec?.delegation_signed === 'boolean') {
        body += kvRow('DNSSEC', data.dnssec.delegation_signed ? 'Delegation signed (registry)' : 'Unsigned delegation (registry)');
      }
      if (typeof data.dnssec?.zone_signed === 'boolean') {
        body += kvRow('ZONE SIGNED', data.dnssec.zone_signed ? 'Yes (registry)' : 'No (registry)');
      }
      if (typeof data.dnssec?.delegation_signed === 'boolean' || typeof data.dnssec?.zone_signed === 'boolean') {
        body += '<p class="result-note">Registry declaration; DNSSEC validation has not been performed.</p>';
      }
    }
    if (Array.isArray(data.statuses) && data.statuses.length) body += kvRow('STATUS', data.statuses.join('\n'));
    for (const contact of Array.isArray(data.abuse_contacts) ? data.abuse_contacts : []) {
      if (contact.name) body += kvRow('ABUSE CONTACT', contact.name);
      if (contact.email) body += kvRow('ABUSE EMAIL', contact.email);
      if (contact.phone) body += kvRow('ABUSE PHONE', contact.phone);
    }
    if (data.raw) body += rawBlock(data.raw);
    return openDetails('whois', 'success', body, { open: true });
  }
  if (data) {
    return openDetails('whois', 'success', preLines([String(data)]));
  }
  return openDetails('whois', 'error', `<div style="color:var(--phos-50)">No WHOIS data returned.</div>`);
}

function dnsEvidenceNote(detail) {
  if (!detail) return '';
  const outcomes = {answer: 'ANSWER', nxdomain: 'NXDOMAIN — name does not exist', nodata: 'NODATA — no records of this type', error: 'LOOKUP FAILED'};
  let html = `<p class="result-note"><strong>${escapeHTML(outcomes[detail.status] || detail.status || 'Unknown outcome')}</strong>`;
  if (detail.query_name) html += `<br>${escapeHTML(detail.query_name)} · ${escapeHTML(detail.query_type || '')}`;
  if (detail.rcode) html += ` · ${escapeHTML(detail.rcode)}`;
  if (detail.resolver) html += `<br>Resolver ${escapeHTML(detail.resolver)}${detail.transport ? ` (${escapeHTML(detail.transport.toUpperCase())})` : ''}`;
  if (detail.observed_at && !Number.isNaN(Date.parse(detail.observed_at))) {
    html += `<br>Observed ${escapeHTML(new Date(detail.observed_at).toISOString().replace('T', ' ').replace('.000Z', ' UTC'))}`;
  }
  if (detail.negative_ttl !== undefined) html += `<br>Negative-cache TTL ${escapeHTML(detail.negative_ttl)} s at observation`;
  if (detail.error) html += `<br>${escapeHTML(detail.error)}`;
  html += '</p>';
  for (const alias of Array.isArray(detail.aliases) ? detail.aliases : []) {
    html += `<p class="result-note">CNAME ${escapeHTML(alias.name)} → ${escapeHTML(alias.value)} · TTL ${escapeHTML(alias.ttl)} s</p>`;
  }
  return html;
}

function renderDns(data, evidence = {}) {
  if (data?.error && Object.keys(evidence).length === 0) return errorDetails('dns', data.error);
  const types = [...new Set([...Object.keys(data || {}), ...Object.keys(evidence)])].filter(type => type !== 'error');
  if (types.length > 0) {
    let inner = '';
    let hasFindings = Boolean(data?.error);
    if (data?.error) inner += `<div class="findings findings--err">${escapeHTML(data.error)}</div>`;
    if (Object.keys(evidence).length) inner += '<p class="result-note">TTL values are seconds remaining when observed. DNSSEC signatures have not been validated by this application.</p>';
    for (const type of types) {
      const val = data?.[type] || [];
      const detail = evidence[type];
      hasFindings ||= detail?.status === 'error';
      inner += `<div class="dns-type">${escapeHTML(type)}</div><div class="dns-values">`;
      inner += dnsEvidenceNote(detail);
      if (Array.isArray(val)) {
        if (type === 'MX' && val.some((record) => /^0\s+\.$/.test(String(record).trim()))) {
          hasFindings ||= val.length > 1;
          inner += `<p class="result-note">${val.length === 1
            ? 'This domain does not accept email (Null MX).'
            : 'Null MX conflicts with other MX records; mail delivery policy is invalid.'}</p>`;
        }
        val.forEach((v) => {
          const record = String(v);
          if (/^v=spf1\b/i.test(record)) inner += spfRecord(record);
          else if (/^v=dmarc1\b/i.test(record)) inner += dmarcRecord(record);
          else inner += `<div class="dns-record"><span class="clickable-record">${escapeHTML(record)}</span>${/^(?:[a-z0-9-]+\.)+[a-z]{2,}\.?$/i.test(record) ? queryButton(record.replace(/\.$/, '')) : ''}</div>`;
          const records = Array.isArray(detail?.records) ? detail.records.filter(rr => rr.value === record) : [];
          for (const rr of records) inner += `<div class="result-note">${escapeHTML(rr.name)} · TTL ${escapeHTML(rr.ttl)} s</div>`;
        });
      } else if (type === 'Subdomains') {
        inner += `<div style="color:var(--phos-50)">Found ${Object.keys(val).length} prefixes</div>`;
      } else {
        inner += `<div class="clickable-record">${escapeHTML(JSON.stringify(val))}</div>`;
      }
      inner += '</div>';
    }
    return openDetails('dns', hasFindings ? 'error' : 'success', inner, { open: true });
  }
  return openDetails('dns', 'success', '<p class="result-note">No records returned. This response does not include an authoritative absence reason.</p>');
}

function renderSubdomains(data) {
  if (data && typeof data === 'object' && data.error) {
    return errorDetails('subdomains', data.error);
  }
  if (data && Object.keys(data).length > 0) {
    let inner = '';
    for (const [fqdn, records] of Object.entries(data)) {
      inner += `<div style="margin-bottom:10px;border-bottom:1px dashed var(--line);padding-bottom:6px">
        <div class="queryable-host"><span class="clickable-record clickable-record--hot">${escapeHTML(fqdn)}</span>${queryButton(fqdn)}</div>`;
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
    ? `<div class="ping-chart"><canvas id="${chartId}" aria-label="Ping round-trip time chart" aria-describedby="${chartId}-summary"></canvas></div>` : '';
  const avg = rtts.length ? (rtts.reduce((a, b) => a + b, 0) / rtts.length).toFixed(1) : null;
  const body = `
    ${failed ? `<div class="findings findings--err">${escapeHTML(errorMessage || 'Ping failed.')}</div>` : ''}
    ${avg ? `<div class="chips" id="${chartId}-summary"><span class="chip chip--ok">AVG ${avg} ms</span><span class="chip">MIN ${Math.min(...rtts)} ms</span><span class="chip">MAX ${Math.max(...rtts)} ms</span><span class="chip">N=${rtts.length}</span></div>` : ''}
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
  const failed = score < 60 || (data.issues || []).length > 0;
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
    ${kvRow('DNS IDENTITIES', (data.sans || []).join(', ') || 'Not provided')}
    ${data.ip_sans?.length ? kvRow('IP IDENTITIES', data.ip_sans.join(', ')) : ''}
    ${kvRow('OCSP (reported)', data.ocsp_status || 'Not provided', { copy: false })}
    ${data.ocsp_freshness ? kvRow('OCSP FRESHNESS', data.ocsp_freshness, { copy: false }) : ''}
    ${typeof data.ocsp_verified === 'boolean' && data.ocsp_freshness ? kvRow('OCSP SIGNER', data.ocsp_verified ? 'Signature and signer authorized' : 'Not verified', { copy: false }) : ''}
    ${data.ocsp_this_update ? kvRow('OCSP THIS UPDATE', data.ocsp_this_update) : ''}
    ${data.ocsp_next_update ? kvRow('OCSP NEXT UPDATE', data.ocsp_next_update) : ''}
    ${data.ocsp_verification_error ? `<p class="result-note">${escapeHTML(data.ocsp_verification_error)}</p>` : ''}
    ${kvRow('SCT / ALPN', `${data.sct_count ?? 0} · ${data.alpn || 'n/a'}`, { copy: false })}
    ${data.verification_error ? `<div class="findings findings--err"><strong>VERIFICATION ERROR</strong>${escapeHTML(data.verification_error)}</div>` : ''}
    ${issues ? `<div class="findings"><strong>ATTENTION NEEDED</strong><ul>${issues}</ul></div>` : '<div class="findings findings--ok"><strong>POSTURE</strong>No immediate TLS issues detected.</div>'}
    <details style="margin-top:8px"><summary><small>CERTIFICATE CHAIN &amp; SANS</small></summary><pre class="raw-block">${escapeHTML(JSON.stringify({ chain: data.chain, sans: data.sans, ip_sans: data.ip_sans }, null, 2))}</pre></details>
    ${data.pem ? `<details style="margin-top:6px"><summary><small>PEM CERTIFICATE</small></summary><pre class="raw-block">${escapeHTML(data.pem)}</pre></details>` : ''}`;
  return openDetails('ssl', failed ? 'error' : 'success', body);
}

function renderHttp(data) {
  if (data.error) return errorDetails('http', data.error);
  const score = Number(data.score);
  const failed = score < 60 || (data.issues || []).length > 0;
  let securityRows = '';
  for (const [header, val] of Object.entries(data.security || {})) {
    const isSet = val !== 'Not Set';
    const notApplicable = /^Not (?:required|applicable)\b/.test(val);
    securityRows += `<dl class="kv"><dt>${escapeHTML(header)}</dt><dd><span class="chip ${notApplicable ? '' : isSet ? 'chip--ok' : 'chip--bad'}">${notApplicable ? 'N/A' : isSet ? 'SET' : 'MISSING'}</span>${isSet ? ` <span class="clickable-record">${escapeHTML(val)}</span>` : ''}</dd></dl>`;
  }
  const issues = (data.issues || []).map((i) => `<li>${escapeHTML(i)}</li>`).join('');
  const redirects = (data.redirects || [])
    .map((r) => `<li><span class="chip">${escapeHTML(r.status)}</span> ${escapeHTML(r.url)} → ${escapeHTML(r.location || '')}</li>`).join('');
  const cookies = (data.cookies || [])
    .map((c) => `<li><strong>${escapeHTML(c.name)}</strong> · ${c.secure ? 'Secure' : 'not Secure'} · ${c.http_only ? 'HttpOnly' : 'no HttpOnly'} · SameSite=${escapeHTML(c.same_site || 'n/a')}</li>`).join('');
  const checks = (data.security_checks || []).map((check) => {
    const tone = check.status === 'pass' ? 'chip--ok' : check.status === 'not-applicable' ? '' : (check.status === 'warning' ? 'chip--warn' : 'chip--bad');
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
      .map((sub) => `<li class="queryable-host"><span class="clickable-record">▸ ${escapeHTML(sub)}</span>${queryButton(sub)}</li>`).join('');
    return openDetails('ct', 'success', `<ul style="font-size:11px">${items}</ul>`);
  }
  return openDetails('ct', 'success', `<div style="color:var(--phos-50)">No subdomains found in CT logs.</div>`);
}

export function renderService(service, data, target, section, evidence) {
  if (data && typeof data === 'object' && data.status === 'skipped') {
    return skippedDetails(service, '', typeof data.reason === 'string' ? data.reason : '');
  }
  switch (service) {
    case 'target': return renderTarget(data);
    case 'geo': return renderGeo(data);
    case 'whois': return renderWhois(data);
    case 'dns': return renderDns(data, evidence);
    case 'subdomains': return renderSubdomains(data);
    case 'portscan': return renderPortscan(data);
    case 'ping': return renderPing(data, target, section);
    case 'route': return renderRoute(data);
    case 'trace': return renderTrace(data);
    case 'ssl': return renderSsl(data);
    case 'http': return renderHttp(data);
    case 'ct': return renderCt(data);
    default: return openDetails(service, 'success', preLines([JSON.stringify(data, null, 2)]));
  }
}

export function skeletonHtml() {
  return `<div class="skel" aria-hidden="true"><i style="width:88%"></i><i style="width:64%"></i><i style="width:76%"></i></div>`;
}

export function skippedDetails(service, reason = '', explanation = '') {
  const messages = {
    'profile-only': 'Skipped because this target is available for profile inspection only.',
    'invalid-target': 'Skipped because the target is invalid.',
    'policy-blocked': 'Skipped because network queries for this target are disabled by server policy.',
    failed: 'No result was returned before the diagnostic request failed.',
    interrupted: 'No result was returned before the diagnostic stream was interrupted.',
  };
  const message = explanation || messages[reason] || 'No result was returned by this module.';
  return openDetails(service, 'skipped', `<div class="module-skipped"><strong>SKIPPED</strong> ${escapeHTML(message)}</div>`, { open: Boolean(reason || explanation) });
}
