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
