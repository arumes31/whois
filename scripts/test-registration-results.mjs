import assert from 'node:assert/strict';
import { parseFragment } from 'parse5';
import { renderService } from '../static/js/render.js';

function render(data) { return renderService('whois', data, 'example.com', { dataset: {} }); }

const network = render({
  kind: 'ip', source: 'rdap', source_url: 'https://rdap.example/ip/1.1.1.1',
  queried_at: '2026-10-09T15:00:00Z', raw: '{"objectClassName":"ip network"}',
  organization: 'Example Network', network: {name: 'EXAMPLE-NET', handle: 'NET-1',
    start_address: '1.1.1.0', end_address: '1.1.1.255', country: 'AU', ip_version: 'v4'},
  abuse_contacts: [{email: 'abuse@example.test', phone: '+1 555 0100'}],
});
assert.match(network, /1\.1\.1\.0/);
assert.match(network, /1\.1\.1\.255/);
assert.match(network, /EXAMPLE-NET/);
assert.match(network, /Example Network/);
assert.match(network, /REGISTRY COUNTRY/);
assert.match(network, /abuse@example\.test/);
assert.match(network, /Registry response/);
assert.doesNotMatch(network, /REGISTRAR|EXPIRES/);

const domain = render({kind: 'domain', source: 'rdap', domain: 'example.com',
  statuses: ['client transfer prohibited'], nameservers: ['ns1.example.net'],
  dnssec: {delegation_signed: false}, registrar: 'Example Registrar', raw: '{}'});
assert.match(domain, /client transfer prohibited/);
assert.match(domain, /ns1\.example\.net/);
assert.match(domain, /Unsigned delegation/);
assert.match(domain, /validation has not been performed/);
assert.doesNotMatch(render({kind: 'domain', dnssec: {}, raw: '{}'}), /Unsigned delegation/);

const malicious = render({kind: 'ip', source: '<img src=x onerror=alert(1)>',
  source_url: 'javascript:alert(1)', organization: '<script>bad()</script>',
  network: {name: '<img src=x>'}, abuse_contacts: [{email: '<img src=x>'}], raw: '<svg onload=bad()>'});
function inspect(node) {
  assert.ok(!['img', 'script', 'svg'].includes(node.tagName), 'untrusted markup must remain text');
  for (const attr of node.attrs || []) {
    assert.ok(!attr.name.startsWith('on'));
    if (attr.name === 'href') assert.match(attr.value, /^https?:\/\//);
  }
  for (const child of node.childNodes || []) inspect(child);
}
inspect(parseFragment(malicious));
assert.doesNotMatch(malicious, /href="javascript:/);

const nullMX = renderService('dns', {MX: ['0 .']}, 'example.com', { dataset: {} });
assert.match(nullMX, /0 \./);
assert.match(nullMX, /does not accept email/);
assert.match(nullMX, /data-status="success"/);
const conflictingMX = renderService('dns', {MX: ['0 .', '10 mail.example.com']}, 'example.com', { dataset: {} });
assert.match(conflictingMX, /conflicts with other MX records/);
assert.doesNotMatch(conflictingMX, /does not accept email/);
assert.match(conflictingMX, /data-status="error"/, 'an invalid mail policy is a finding, not a clean result');
console.log('Registration and no-service DNS result rendering passed.');

const subdomain = render({query: 'www.example.com', domain: 'example.com', source: 'rdap', raw: '{}'});
assert.match(subdomain, /www\.example\.com/);
assert.match(subdomain, /Registration belongs to the registered domain/);

const geo = {query: 'example.com', ip: '1.1.1.1', lat: 0, lon: 0, source: 'GeoLite2 City (local)'};
const missingGeo = renderService('geo', {...geo, has_coordinates: false});
assert.doesNotMatch(missingGeo, /COORDINATES/);
assert.match(missingGeo, /1\.1\.1\.1/);
assert.match(missingGeo, /estimated/);
assert.match(renderService('geo', {...geo, has_coordinates: true}), /COORDINATES/);
assert.match(renderService('geo', {error: 'No record for this address'}), /No record for this address/);

const dnsEvidence = {
  A: {status: 'answer', query_name: 'example.com.', query_type: 'A', rcode: 'NOERROR', resolver: '1.1.1.1:53', transport: 'udp', observed_at: '2026-10-09T15:00:00Z', records: [{name: 'example.com.', value: '1.1.1.1', ttl: 0}]},
  AAAA: {status: 'nodata', query_name: 'example.com.', query_type: 'AAAA', rcode: 'NOERROR'},
  MX: {status: 'error', error: 'resolver timed out'},
  DMARC: {status: 'nxdomain', query_name: '_dmarc.example.com.', query_type: 'TXT', rcode: 'NXDOMAIN'},
};
const detailedDns = renderService('dns', {A: ['1.1.1.1']}, 'example.com', {}, dnsEvidence);
for (const text of ['TTL 0 s', 'NODATA', 'NXDOMAIN', 'resolver timed out', '1.1.1.1:53', '_dmarc.example.com.']) assert.ok(detailedDns.includes(text), text);
assert.match(detailedDns, /data-status="error"/);
for (const [name, detail, missingAlias] of [
  ['alias target absent', {query_type: 'A', aliases: [{name: 'alias.example.com.', value: 'missing.example.com.', ttl: 15}]}, true],
  ['original name absent', {query_type: 'A'}, false],
  ['CNAME answer with absent target', {query_type: 'CNAME', records: [{name: 'alias.example.com.', value: 'missing.example.com.', ttl: 15}]}, true],
  ['CNAME name itself absent', {query_type: 'CNAME', records: []}, false],
  ['other records are not alias evidence', {query_type: 'A', records: [{name: 'example.com.', value: '1.1.1.1', ttl: 15}]}, false],
]) {
  const html = renderService('dns', {}, '', {}, {A: {status: 'nxdomain', query_name: 'example.com.', rcode: 'NXDOMAIN', ...detail}});
  assert.match(html, missingAlias ? /NXDOMAIN — alias target does not exist/ : /NXDOMAIN — queried name does not exist/, name);
  assert.doesNotMatch(html, missingAlias ? /NXDOMAIN — (?:queried )?name does not exist/ : /NXDOMAIN — alias target does not exist/, name);
  assert.match(html, /data-status="success"/, 'a negative DNS answer is not an upstream failure');
}
assert.match(renderService('dns', {A: ['1.1.1.1'], error: 'context deadline exceeded'}, '', {}, {A: dnsEvidence.A}), /context deadline exceeded/);
assert.match(render({kind: 'domain', dnssec: {zone_signed: true}}), /ZONE SIGNED/);
assert.match(renderService('http', {score: 100, security: {'X-Frame-Options': 'Not required (CSP frame-ancestors)'}, security_checks: [{name: 'X-Frame-Options', status: 'not-applicable'}]}), />N\/A</);
inspect(parseFragment(renderService('dns', {}, '', {}, {TXT: {status: 'error', error: '<script>bad()</script>', resolver: '<img src=x>'}})));

const ssl = renderService('ssl', {score: 100, verified: true, hostname_valid: true,
  protocol: 'TLS1.3', sans: ['example.com'], ip_sans: ['2001:4860::8888'],
  ocsp_status: 'good', ocsp_freshness: 'stale', ocsp_verified: true, issues: ['OCSP response expired']});
assert.match(ssl, /2001:4860::8888/);
assert.match(ssl, /stale/);
assert.match(ssl, /reported/);
assert.match(ssl, /data-status="error"/);
console.log('DNS, location, registration target and certificate evidence rendering passed.');
