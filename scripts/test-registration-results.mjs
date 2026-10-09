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

const subnet4 = { version: 4, cidr: '192.168.1.0/24', prefix_length: 24, input_address: '192.168.1.129',
  network: '192.168.1.0', last_address: '192.168.1.255', address_count: '256', netmask: '255.255.255.0',
  wildcard_mask: '0.0.0.255', broadcast: '192.168.1.255', first_usable: '192.168.1.1', last_usable: '192.168.1.254', usable_count: '254', notes: ['Usable host convention excludes network and broadcast.'] };
const subnetHtml = renderService('target', { valid: true, kind: 'cidr', subnet: subnet4 });
for (const text of ['Subnet calculation', '192.168.1.129', '255.255.255.0', '0.0.0.255', 'First usable', 'Last usable', '254', 'Usable host convention', 'Calculated locally']) assert.ok(subnetHtml.includes(text), text);
const subnet6 = renderService('target', { valid: true, kind: 'cidr', subnet: { version: 6, cidr: '::/0', prefix_length: 0, input_address: '::', network: '::', last_address: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', address_count: '340282366920938463463374607431768211456', notes: ['IPv6 has no broadcast address.'] } });
assert.match(subnet6, /340282366920938463463374607431768211456/);
assert.doesNotMatch(subnet6, /<dt>Broadcast|<dt>Netmask|<dt>Usable/);
inspect(parseFragment(renderService('target', { valid: true, subnet: { ...subnet4, notes: ['<script>bad()</script>'] } })));

const asnInfo = { status: 'answer', source: 'RIPEstat / RIPE RIS', fetched_at: '2026-10-09T12:00:00Z',
  asn: { number: 13335, holder: 'Example network', announced: false, min_peers_seeing: 10,
    overview_start: '2026-10-09T08:00:00Z', overview_end: '2026-10-09T12:00:00Z',
    prefixes: { status: 'answer', items: Array.from({length: 102}, (_, n) => `11.0.${n}.0/24`), period_start: '2026-10-08T12:00:00Z', period_end: '2026-10-09T12:00:00Z', fetched_at: '2026-10-09T12:00:01Z', source_url: 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS13335' } } };
const asnHtml = renderService('routing', asnInfo);
for (const text of ['AS13335', 'Example network', '10 RIS', 'does not establish inactivity', 'Observed prefixes', '102', 'Browse first 100', 'export', 'last 24 hours', '2026-10-08 12:00:00 UTC']) assert.ok(asnHtml.includes(text), text);
assert.match(asnHtml, /<details><summary>Browse first 100 of 102 prefixes/);
assert.match(asnHtml, /11\.0\.99\.0\/24/);
assert.doesNotMatch(asnHtml, /11\.0\.100\.0\/24|8 hours|currently announced/);
const prefixError = renderService('routing', { ...asnInfo, asn: { ...asnInfo.asn, prefixes: { status: 'error', error: 'Prefix request failed' } } });
assert.match(prefixError, /Example network/);
assert.match(prefixError, /Prefix request failed/);
assert.match(prefixError, /data-status="error"/);
const emptyPrefixes = renderService('routing', { ...asnInfo, asn: { ...asnInfo.asn, prefixes: { ...asnInfo.asn.prefixes, items: [] } } });
assert.match(emptyPrefixes, /No prefixes observed during this period/);
assert.doesNotMatch(emptyPrefixes, /MODULE FAULT/);
inspect(parseFragment(renderService('routing', { ...asnInfo, asn: { ...asnInfo.asn, holder: '<img src=x>', prefixes: { ...asnInfo.asn.prefixes, items: ['<script>bad()</script>'] } } })));
console.log('Subnet and ASN evidence rendering passed.');
