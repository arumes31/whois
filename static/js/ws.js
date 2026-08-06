// WebSocket transport: reconnect with backoff, heartbeat, offline queue.

const MAX_QUEUED_MESSAGES = 50;

let socket;
let messageQueue = [];
let reconnectTimer;
let reconnectAttempts = 0;
let heartbeatTimer;
let pageUnloading = false;
let messageHandler = () => {};
let logHandler = () => {};

export function onMessage(handler) { messageHandler = handler; }
export function onTransportLog(handler) { logHandler = handler; }

function transportLog(message) {
  logHandler(message);
}

function clearHeartbeat() {
  if (!heartbeatTimer) return;
  window.clearInterval(heartbeatTimer);
  heartbeatTimer = undefined;
}

function scheduleReconnect(delay) {
  if (pageUnloading || reconnectTimer) return;
  const backoff = delay ?? Math.min(30000, 1000 * (2 ** Math.min(reconnectAttempts, 5)));
  const jitter = delay === 0 ? 0 : Math.floor(Math.random() * 500);
  reconnectAttempts += 1;
  reconnectTimer = window.setTimeout(() => {
    reconnectTimer = undefined;
    connect();
  }, backoff + jitter);
}

export function queueMessage(data) {
  if (messageQueue.length >= MAX_QUEUED_MESSAGES) {
    messageQueue.shift();
    transportLog('The oldest queued scan was discarded while reconnecting.');
  }
  messageQueue.push(data);
}

export function connect() {
  if (pageUnloading || (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING))) return;
  if (reconnectTimer) {
    window.clearTimeout(reconnectTimer);
    reconnectTimer = undefined;
  }
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  let connection;
  try {
    connection = new WebSocket(`${proto}//${window.location.host}/ws`);
    socket = connection;
  } catch (error) {
    console.error('WebSocket creation failed:', error);
    scheduleReconnect();
    return;
  }

  connection.onopen = () => {
    if (socket !== connection) return;
    reconnectAttempts = 0;
    transportLog('Uplink established.');
    while (messageQueue.length > 0 && connection.readyState === WebSocket.OPEN) {
      try {
        connection.send(JSON.stringify(messageQueue[0]));
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
        connection.send(JSON.stringify({ type: 'heartbeat' }));
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
    messageHandler(msg);
  };

  connection.onclose = (event) => {
    if (socket !== connection) return;
    socket = undefined;
    clearHeartbeat();
    if (!event.wasClean) {
      transportLog(`Uplink dropped (code ${event.code}). Re-establishing...`);
    }
    scheduleReconnect();
  };

  connection.onerror = () => {
    if (socket !== connection) return;
    transportLog('Uplink protocol error. Check proxy headers.');
  };
}

export function send(data) {
  if (socket && socket.readyState === WebSocket.OPEN) {
    try {
      socket.send(JSON.stringify(data));
      return;
    } catch (error) {
      console.warn('Send failed; message queued:', error);
      socket.close();
    }
  }
  queueMessage(data);
  scheduleReconnect(0);
}

window.addEventListener('beforeunload', () => {
  pageUnloading = true;
  clearHeartbeat();
  if (reconnectTimer) window.clearTimeout(reconnectTimer);
  if (socket && socket.readyState === WebSocket.OPEN) socket.close(1000, 'Page unloading');
});

window.addEventListener('pageshow', (event) => {
  pageUnloading = false;
  if (event.persisted) scheduleReconnect(0);
});
