import assert from 'node:assert/strict';

import {
  canonicalTargetIdentity, createRequestID, fetchWithCSRF, splitTargets,
} from '../static/js/util.js';
import { renderService } from '../static/js/render.js';
import * as store from '../static/js/store.js';
import * as cards from '../static/js/cards.js';

function testCanonicalTargets() {
  const cases = [
    ['Example.COM.', '|example.com'],
    ['192.0.2.129/24', 'prefix|192.0.2.0/24'],
    ['192.0.2.1/0', 'prefix|0.0.0.0/0'],
    ['2001:0db8:0:0:0:0:0:1', '|2001:db8::1'],
    ['2001:db8::ffff/64', 'prefix|2001:db8::/64'],
    ['2001:0db8:0:0:ffff:ffff:ffff:ffff/64', 'prefix|2001:db8::/64'],
    ['::ffff:192.0.2.1', '|192.0.2.1'],
    ['::ffff:c000:0201', '|192.0.2.1'],
    ['::ffff:192.0.2.129/120', 'prefix|::ffff:192.0.2.0/120'],
    ['[192.0.2.1]', '|192.0.2.1'],
    ['https://[2001:0db8::1]:8443/path', 'https|[2001:db8::1]:8443'],
    ['192.0.2.1/032', 'http|192.0.2.1'],
    ['2001:db8::1/064', 'invalid|2001:db8::1/064'],
    ['[2001:db8::1]/64', 'http|2001:db8::1'],
    ['fe80:0:0:0:0:0:0:1%eth0', '|fe80::1%eth0'],
    ['fe80::1%ETH0', '|fe80::1%ETH0'],
    ['[192.0.2.1].', 'invalid|[192.0.2.1].'],
    ['[2001:db8::1].', 'invalid|[2001:db8::1].'],
    ['192.0.002.001', '|192.0.002.001'],
    ['0300.0000.0002.0001', '|0300.0000.0002.0001'],
    ['127.1', '|127.1'],
    ['0x7f000001', 'invalid|0x7f000001'],
    ['example.com:80', '|example.com:80'],
    ['example.com:080', '|example.com:080'],
    ['example.com:', 'invalid|example.com:'],
    ['https://example.com:443/path', 'https|example.com:443'],
  ];
  cases.forEach(([input, expected]) => assert.equal(canonicalTargetIdentity(input), expected, input));
  assert.equal(splitTargets('Example.com, example.COM.').length, 1);
  assert.equal(splitTargets('2001:db8::1, 2001:0db8:0:0:0:0:0:1').length, 1);
  assert.equal(splitTargets('192.0.2.129/24, 192.0.2.1/24').length, 1);
  assert.equal(splitTargets('[192.0.2.1], 192.0.2.1').length, 1);
  assert.equal(splitTargets('192.0.2.1::, c000:201::').length, 2, 'invalid IPv4-before-:: must not collide');
  assert.equal(splitTargets('192.0.2.1/032, 192.0.2.1/32').length, 2, 'leading-zero prefix must not collide');
  assert.equal(splitTargets('2001:db8::1/064, 2001:db8::1/64').length, 2, 'invalid IPv6 prefix must not collide');
  assert.equal(splitTargets('[2001:db8::1]/64, 2001:db8::/64').length, 2, 'bracketed URL path must not collide with a prefix');
  assert.equal(splitTargets('fe80:0:0:0:0:0:0:1%eth0, fe80::1%eth0').length, 1);
  assert.equal(splitTargets('fe80::1%eth0, fe80::1%ETH0').length, 2, 'zone identity is case-sensitive');
  assert.equal(splitTargets('[192.0.2.1]., 192.0.2.1').length, 2, 'invalid bracket-dot form must not collide');
  assert.equal(splitTargets('192.0.002.001, 192.0.2.1').length, 2, 'legacy IPv4-looking domain must not be rewritten');
  assert.equal(splitTargets('example.com, example.com:80').length, 2, 'explicit default port must be preserved');
  assert.equal(splitTargets('example.com:, example.com').length, 2, 'empty port must remain invalid and distinct');
  assert.match(createRequestID(), /^[A-Za-z0-9._:-]{1,128}$/);
}

function testGenerationState() {
  const config = { dns: true, ports: '' };
  store.beginScan('generation.test', {
    requestID: 'generation-old', identity: '|generation.test', config, total: 1,
  });
  store.getResults('generation.test').dns = { A: ['192.0.2.1'] };
  store.beginScan('generation.test', {
    requestID: 'generation-current', identity: '|generation.test', config, total: 1,
  });
  assert.equal(store.getScanByRequestID('generation-old'), null);
  assert.equal(store.getScanByRequestID('generation-current')?.status, 'queued');
  assert.deepEqual(store.getResults('generation.test'), {});
}

function testErrorRendering() {
  const cases = [
    ['whois', 'WHOIS error: timeout', 'timeout'],
    ['subdomains', { error: 'resolver failed' }, 'resolver failed'],
    ['portscan', { error: 'unknown port preset' }, 'unknown port preset'],
    ['portscan', 'Error: invalid port', 'invalid port'],
    ['ping', 'Error: ping unavailable', 'ping unavailable'],
    ['route', 'Error: traceroute unavailable', 'traceroute unavailable'],
  ];
  cases.forEach(([service, payload, expected]) => {
    const html = renderService(service, payload, 'example.test', { dataset: {} });
    assert.match(html, /data-status="error"/);
    assert.ok(html.includes(expected), `${service} should retain its error text`);
  });
  const dnsPolicy = renderService('dns', {
    TXT: ['v=spf1 include:_spf.example.test -all', 'v=DMARC1; p=reject; pct=100'],
  }, 'example.test', { dataset: {} });
  assert.match(dnsPolicy, /SPF POLICY/);
  assert.match(dnsPolicy, /DMARC STRENGTH/);
  assert.match(dnsPolicy, /ENFORCED/);

  const target = renderService('target', {
    valid: true,
    input: '192.0.2.1',
    normalized: '192.0.2.1',
    ips: [{ version: 4, address: '192.0.2.1', scope: 'documentation', reverse_dns: ['ptr.example.test'] }],
  }, '192.0.2.1', { dataset: {} });
  assert.match(target, /data-query-target="ptr\.example\.test"/);
}

const listeners = new Map();
const timers = new Map();
let nextTimer = 1;

globalThis.window = {
  location: { protocol: 'http:', host: 'example.test' },
  addEventListener(type, handler) { listeners.set(type, handler); },
  setTimeout(handler) {
    const id = nextTimer;
    nextTimer += 1;
    timers.set(id, { handler, kind: 'timeout' });
    return id;
  },
  clearTimeout(id) { timers.delete(id); },
  setInterval(handler) {
    const id = nextTimer;
    nextTimer += 1;
    timers.set(id, { handler, kind: 'interval' });
    return id;
  },
  clearInterval(id) { timers.delete(id); },
  dispatchEvent() {},
};

const systemStatus = {
  dataset: {},
  classList: { toggle() {} },
  textContent: '',
};
globalThis.document = { getElementById() { return systemStatus; } };

class MockWebSocket {
  static CONNECTING = 0;

  static OPEN = 1;

  static CLOSING = 2;

  static CLOSED = 3;

  static instances = [];

  constructor(url) {
    this.url = url;
    this.readyState = MockWebSocket.CONNECTING;
    this.sent = [];
    MockWebSocket.instances.push(this);
  }

  send(payload) {
    if (this.readyState !== MockWebSocket.OPEN) throw new Error('socket is not open');
    this.sent.push(JSON.parse(payload));
  }

  close() { this.readyState = MockWebSocket.CLOSING; }
}
globalThis.WebSocket = MockWebSocket;

const ws = await import('../static/js/ws.js?frontend-state-test');
const requestEvents = [];
ws.onRequestEvent((event) => requestEvents.push(event));
ws.onMessage(() => false);

function openConnection() {
  ws.connect();
  const connection = MockWebSocket.instances.at(-1);
  connection.readyState = MockWebSocket.OPEN;
  connection.onopen();
  return connection;
}

function closeConnection(connection, code = 1006) {
  connection.readyState = MockWebSocket.CLOSED;
  connection.onclose({ wasClean: code === 1000, code });
}

function message(connection, payload) {
  connection.onmessage({ data: JSON.stringify(payload) });
}

function eventsFor(requestID) {
  return requestEvents.filter((event) => event.request_id === requestID).map((event) => event.type);
}

function testQueue() {
  for (let index = 0; index < 50; index += 1) {
    assert.equal(ws.queueMessage({ request_id: `queue-${index}`, targets: [`${index}.test`] }), true);
  }
  assert.equal(ws.queueMessage({ request_id: 'queue-overflow', targets: ['overflow.test'] }), false);
  assert.deepEqual(eventsFor('queue-overflow'), ['rejected']);
  for (let index = 0; index < 50; index += 1) assert.equal(ws.cancelQueued(`queue-${index}`), true);
  assert.equal(ws.queueMessage({ request_id: '-_.:', targets: ['punctuation.test'] }), true);
  assert.equal(ws.cancelQueued('-_.:'), true);
  requestEvents.length = 0;
  assert.equal(ws.queueMessage({ request_id: 'cancel-all-a', targets: ['a.test'] }), true);
  assert.equal(ws.queueMessage({ request_id: 'cancel-all-b', targets: ['b.test'] }), true);
  assert.equal(ws.cancelAll(), true);
  assert.deepEqual(eventsFor('cancel-all-a'), ['queued', 'interrupted']);
  assert.deepEqual(eventsFor('cancel-all-b'), ['queued', 'interrupted']);
}

function testMultiTargetTracking() {
  requestEvents.length = 0;
  const connection = openConnection();
  assert.equal(ws.send({
    request_id: 'multi-target', targets: ['one.test', 'two.test'], config: { dns: true },
  }), true);
  message(connection, { type: 'all_done', request_id: 'multi-target', target: 'one.test' });
  closeConnection(connection);
  assert.deepEqual(eventsFor('multi-target'), ['sent', 'interrupted']);

  requestEvents.length = 0;
  const canonicalConnection = openConnection();
  ws.send({
    request_id: 'canonical-multi',
    targets: ['2001:db8::1', '2001:0db8:0:0:0:0:0:1'],
    config: { dns: true },
  });
  message(canonicalConnection, {
    type: 'all_done', request_id: 'canonical-multi', target: '2001:db8::1',
  });
  closeConnection(canonicalConnection);
  assert.deepEqual(eventsFor('canonical-multi'), ['sent']);

  requestEvents.length = 0;
  const invalidConnection = openConnection();
  ws.send({
    request_id: 'invalid-multi', targets: ['bad target', 'BAD TARGET'], config: { dns: true },
  });
  message(invalidConnection, {
    type: 'all_done', request_id: 'invalid-multi', target: 'bad target',
  });
  closeConnection(invalidConnection);
  assert.deepEqual(eventsFor('invalid-multi'), ['sent', 'interrupted']);
}

function testGlobalErrorAndPageLifecycle() {
  requestEvents.length = 0;
  const errorConnection = openConnection();
  ws.send({ request_id: 'global-error', targets: ['error.test'], config: {} });
  message(errorConnection, { type: 'error', request_id: 'global-error', data: 'too many targets' });
  closeConnection(errorConnection);
  assert.deepEqual(eventsFor('global-error'), ['sent']);

  requestEvents.length = 0;
  const pageConnection = openConnection();
  ws.send({ request_id: 'page-lifecycle', targets: ['page.test'], config: {} });
  assert.equal(listeners.has('beforeunload'), false, 'beforeunload would reduce BFCache eligibility');
  listeners.get('pagehide')({ persisted: true });
  assert.deepEqual(eventsFor('page-lifecycle'), ['sent', 'interrupted']);
  closeConnection(pageConnection, 1000);
  assert.deepEqual(eventsFor('page-lifecycle'), ['sent', 'interrupted'], 'close must not duplicate interruption');

  const instancesBeforeRestore = MockWebSocket.instances.length;
  listeners.get('pageshow')({ persisted: true });
  const reconnect = [...timers.entries()].find(([, timer]) => timer.kind === 'timeout');
  assert.ok(reconnect, 'BFCache restore should schedule an immediate reconnect');
  timers.delete(reconnect[0]);
  reconnect[1].handler();
  assert.equal(MockWebSocket.instances.length, instancesBeforeRestore + 1);
  assert.equal(MockWebSocket.instances.at(-1).readyState, MockWebSocket.CONNECTING);
  listeners.get('pagehide')({ persisted: true });
  assert.equal(MockWebSocket.instances.at(-1).readyState, MockWebSocket.CLOSING);
}

function testRequestLevelUIError() {
  const badge = {};
  const progress = { setAttribute() {} };
  const rescan = {};
  const card = {
    dataset: { target: 'request-error.test' },
    querySelector(selector) {
      if (selector === '.status-badge') return badge;
      if (selector === '.result-card__progress') return progress;
      if (selector === '[data-card-action="rescan"]') return rescan;
      return null;
    },
    querySelectorAll() { return []; },
    setAttribute() {},
  };
  globalThis.document = {
    getElementById() { return null; },
    querySelectorAll(selector) {
      if (selector === '.result-card') return [card];
      return [];
    },
  };
  store.beginScan('request-error.test', {
    requestID: 'request-level-error', identity: '|request-error.test', config: { dns: true }, total: 1,
  });
  assert.equal(cards.routeMessage({
    type: 'error', request_id: 'request-level-error', service: 'system', data: 'request rejected',
  }), true);
  assert.equal(store.getScanByRequestID('request-level-error').status, 'failed');
  assert.equal(badge.textContent, 'FAILED');
}

function terminalCard(target, section) {
  const progressBar = { style: {} };
  const progress = { setAttribute() {} };
  const status = {};
  const finding = { className: '', hidden: true };
  const rescan = {};
  return {
    dataset: { target },
    querySelector(selector) {
      if (selector === '.result-card__progress i') return progressBar;
      if (selector === '.result-card__progress') return progress;
      if (selector === '.status-badge') return status;
      if (selector === '.finding-count') return finding;
      if (selector === '[data-card-action="rescan"]') return rescan;
      return null;
    },
    querySelectorAll(selector) { return selector === '.service-section' ? [section] : []; },
    setAttribute() {},
  };
}

function testSlowModuleTerminalCleanup() {
  ['done', 'all_done', 'error'].forEach((eventType) => {
    const target = `${eventType}.slow.test`;
    const section = {
      dataset: { service: 'dns' },
      innerHTML: '<div class="slow-module">scan is still active</div>',
      querySelector(selector) {
        return selector.includes('.slow-module') && this.innerHTML.includes('slow-module') ? {} : null;
      },
    };
    const card = terminalCard(target, section);
    globalThis.document = {
      getElementById() { return null; },
      querySelectorAll(selector) { return selector === '.result-card' ? [card] : []; },
    };
    store.beginScan(target, {
      requestID: `${eventType}-slow`, identity: `|${target}`, config: { dns: true }, total: 1,
    });
    assert.equal(cards.routeMessage({
      type: eventType, request_id: `${eventType}-slow`, target, service: 'dns', data: 'request failed',
    }), true);
    assert.doesNotMatch(section.innerHTML, /scan is still active|slow-module/);
  });
}

async function testRetryAfterParsing() {
  const events = [];
  globalThis.document = {
    body: { dataset: {} },
    cookie: '',
    querySelector() { return null; },
  };
  window.dispatchEvent = (event) => events.push(event);
  const cases = [
    { header: '12', validate: (value) => assert.equal(value, 12) },
    {
      header: new Date(Date.now() + 5000).toUTCString(),
      validate: (value) => assert.ok(value >= 3 && value <= 5, `HTTP-date delay was ${value}`),
    },
    { header: 'not-a-date', validate: (value) => assert.equal(value, 0) },
  ];
  for (const testCase of cases) {
    window.fetch = async () => new Response('', {
      status: 429,
      headers: { 'Retry-After': testCase.header },
    });
    await fetchWithCSRF('/rate-limited');
    const value = events.pop().detail.retryAfter;
    assert.equal(Number.isNaN(value), false);
    testCase.validate(value);
  }
}

testCanonicalTargets();
testGenerationState();
testErrorRendering();
testQueue();
testMultiTargetTracking();
testGlobalErrorAndPageLifecycle();
testRequestLevelUIError();
testSlowModuleTerminalCleanup();
await testRetryAfterParsing();

console.log('Frontend state/protocol checks passed.');
