// WebSocket transport: reconnect with backoff, heartbeat, offline queue.

import { canonicalTargetIdentity } from './util.js';

const MAX_QUEUED_MESSAGES = 50;

let socket;
let messageQueue = [];
let reconnectTimer;
let reconnectAttempts = 0;
let heartbeatTimer;
let pageHidden = false;
let messageHandler = () => {};
let logHandler = () => {};
let requestEventHandler = () => {};
const sentRequestsBySocket = new WeakMap();

export function onMessage(handler) { messageHandler = handler; }
export function onTransportLog(handler) { logHandler = handler; }
export function onRequestEvent(handler) { requestEventHandler = handler; }

function transportLog(message) {
  logHandler(message);
}

function requestID(data) {
  const id = typeof data?.request_id === 'string' ? data.request_id : '';
  return /^[A-Za-z0-9._:-]{1,128}$/.test(id) ? id : '';
}

function transportTargetIdentity(value) {
  const target = String(value).trim();
  const canonical = canonicalTargetIdentity(target);
  return canonical.startsWith('invalid|') ? `invalid-raw|${target}` : canonical;
}

function emitRequestEvent(type, data, message = '') {
  const id = requestID(data);
  if (!id) return;
  try {
    requestEventHandler({ type, request_id: id, message });
  } catch (error) {
    console.error('Request-state handler failed:', error);
  }
}

function sentRequests(connection) {
  let requests = sentRequestsBySocket.get(connection);
  if (!requests) {
    requests = new Map();
    sentRequestsBySocket.set(connection, requests);
  }
  return requests;
}

function sendRequest(connection, data) {
  connection.send(JSON.stringify(data));
  const id = requestID(data);
  if (id) {
    const targets = new Set((Array.isArray(data.targets) ? data.targets : [])
      .map((target) => String(target).trim())
      .filter(Boolean)
      .map(transportTargetIdentity));
    sentRequests(connection).set(id, targets);
    emitRequestEvent('sent', data);
  }
}

function finishTrackedRequest(connection, message) {
  if (!['all_done', 'error'].includes(message.type)) return;
  const id = requestID(message);
  if (!id) return;
  const requests = sentRequests(connection);
  const targets = requests.get(id);
  if (!targets) return;
  if (message.type === 'error' && !message.target) {
    requests.delete(id);
    return;
  }
  if (typeof message.target !== 'string' || !message.target) return;
  targets.delete(transportTargetIdentity(message.target));
  if (targets.size === 0) requests.delete(id);
}

function interruptSentRequests(connection) {
  const requests = sentRequests(connection);
  requests.forEach((_, id) => {
    try {
      requestEventHandler({
        type: 'interrupted',
        request_id: id,
        message: 'The diagnostic stream was interrupted when the uplink closed.',
      });
    } catch (error) {
      console.error('Request-state handler failed:', error);
    }
  });
  requests.clear();
}

function setConnectionStatus(state, label) {
  const status = document.getElementById('systemStatus');
  if (!status) return;
  status.dataset.state = state;
  status.classList.toggle('system-status--connecting', state === 'connecting');
  status.classList.toggle('system-status--down', state === 'offline');
  if (status.textContent !== label) status.textContent = label;
}

function clearHeartbeat() {
  if (!heartbeatTimer) return;
  window.clearInterval(heartbeatTimer);
  heartbeatTimer = undefined;
}

function scheduleReconnect(delay) {
  if (pageHidden) return;
  if (reconnectTimer && delay === 0) {
    window.clearTimeout(reconnectTimer);
    reconnectTimer = undefined;
  } else if (reconnectTimer) {
    return;
  }
  const backoff = delay ?? Math.min(30000, 1000 * (2 ** Math.min(reconnectAttempts, 5)));
  const jitter = delay === 0 ? 0 : Math.floor(Math.random() * 500);
  reconnectAttempts += 1;
  reconnectTimer = window.setTimeout(() => {
    reconnectTimer = undefined;
    connect();
  }, backoff + jitter);
}

export function queueMessage(data) {
  if (!requestID(data)) {
    transportLog('A scan request without a valid request ID was rejected.');
    return false;
  }
  if (messageQueue.length >= MAX_QUEUED_MESSAGES) {
    const message = 'The offline scan queue is full; this request was not queued.';
    transportLog(message);
    emitRequestEvent('rejected', data, message);
    return false;
  }
  messageQueue.push(data);
  emitRequestEvent('queued', data);
  return true;
}

export function cancelQueued(requestIDValue) {
  const id = String(requestIDValue || '');
  const before = messageQueue.length;
  messageQueue = messageQueue.filter((data) => requestID(data) !== id);
  return messageQueue.length !== before;
}

export function connect() {
  if (pageHidden || (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING))) return;
  if (reconnectTimer) {
    window.clearTimeout(reconnectTimer);
    reconnectTimer = undefined;
  }
  setConnectionStatus('connecting', reconnectAttempts > 0 ? 'SYSTEM RECONNECTING' : 'SYSTEM CONNECTING');
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  let connection;
  try {
    connection = new WebSocket(`${proto}//${window.location.host}/ws`);
    socket = connection;
  } catch (error) {
    console.error('WebSocket creation failed:', error);
    setConnectionStatus('offline', 'SYSTEM OFFLINE');
    scheduleReconnect();
    return;
  }

  connection.onopen = () => {
    if (socket !== connection) return;
    reconnectAttempts = 0;
    setConnectionStatus('online', 'SYSTEM ONLINE');
    transportLog('Uplink established.');
    while (messageQueue.length > 0 && connection.readyState === WebSocket.OPEN) {
      try {
        sendRequest(connection, messageQueue[0]);
        messageQueue.shift();
      } catch (error) {
        console.warn('Failed to flush queued message:', error);
        connection.close();
        break;
      }
    }
    clearHeartbeat();
    heartbeatTimer = window.setInterval(() => {
      if (connection.readyState === WebSocket.OPEN) {
        try {
          connection.send(JSON.stringify({ type: 'heartbeat' }));
        } catch (error) {
          console.warn('Heartbeat failed:', error);
          connection.close();
        }
      }
    }, 25000);
  };

  connection.onmessage = (event) => {
    if (socket !== connection) return;
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch {
      transportLog('A malformed server frame was ignored.');
      return;
    }
    if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') {
      transportLog('An invalid server frame was ignored.');
      return;
    }
    if (msg.type === 'heartbeat') return;
    // Transport ownership is independent from UI generation ownership: stale
    // terminal frames are ignored by the card router but must still release the
    // request ID held for this socket.
    finishTrackedRequest(connection, msg);
    messageHandler(msg);
  };

  connection.onclose = (event) => {
    interruptSentRequests(connection);
    if (socket !== connection) return;
    socket = undefined;
    clearHeartbeat();
    setConnectionStatus('connecting', 'SYSTEM RECONNECTING');
    if (!event.wasClean) {
      transportLog(`Uplink dropped (code ${event.code}). Re-establishing...`);
    }
    scheduleReconnect();
  };

  connection.onerror = () => {
    if (socket !== connection) return;
    setConnectionStatus('offline', 'SYSTEM OFFLINE');
    transportLog('Uplink protocol error. Check proxy headers.');
  };
}

export function send(data) {
  if (!requestID(data)) {
    transportLog('A scan request without a valid request ID was rejected.');
    return false;
  }
  if (socket && socket.readyState === WebSocket.OPEN) {
    try {
      sendRequest(socket, data);
      return true;
    } catch (error) {
      console.warn('Send failed; message queued:', error);
      socket.close();
    }
  }
  const queued = queueMessage(data);
  scheduleReconnect(0);
  return queued;
}

window.addEventListener('pagehide', () => {
  pageHidden = true;
  clearHeartbeat();
  if (reconnectTimer) {
    window.clearTimeout(reconnectTimer);
    reconnectTimer = undefined;
  }
  const connection = socket;
  socket = undefined;
  if (connection) {
    interruptSentRequests(connection);
    if (connection.readyState === WebSocket.OPEN || connection.readyState === WebSocket.CONNECTING) {
      try { connection.close(1000, 'Page hidden'); } catch { /* connection is already closing */ }
    }
  }
});

window.addEventListener('pageshow', (event) => {
  pageHidden = false;
  if (event.persisted) {
    if (socket?.readyState === WebSocket.OPEN) {
      setConnectionStatus('online', 'SYSTEM ONLINE');
    } else {
      setConnectionStatus('connecting', 'SYSTEM RECONNECTING');
      scheduleReconnect(0);
    }
  }
});
