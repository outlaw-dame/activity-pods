'use strict';

// These limits apply to the gateway's application WebSocket surface.
// Frame compression is deliberately disabled in the gateway: zlib cost and
// per-connection memory must be measured before enabling it.
const MAX_INBOUND_BYTES = 256 * 1024;
const MAX_BUFFERED_BYTES = 2 * 1024 * 1024;
const MAX_CONNECTIONS = 2048;
const HEARTBEAT_MS = 30000;
const MAX_ASYNC_MESSAGES = 8;

function canonicalOrigin(value) {
  if (typeof value !== 'string' || !value || value.length > 512) return null;
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== value ||
        url.username || url.password || url.hash || url.search) return null;
    return url.origin;
  } catch { return null; }
}

function allowedOrigins(baseUrl, frontendUrl, extraOrigins = '') {
  const known = new Set();
  for (const candidate of [baseUrl, frontendUrl]) {
    if (typeof candidate !== 'string' || !candidate) continue;
    let uri;
    try { uri = new URL(candidate); }
    catch { throw new Error('Invalid WebSocket provider/frontend origin'); }
    const origin = canonicalOrigin(uri.origin);
    if (!origin) throw new Error('Invalid WebSocket provider/frontend origin');
    known.add(origin);
  }
  if (!known.size) throw new Error('WebSocket origin allowlist is empty');
  if (typeof extraOrigins !== 'string' || extraOrigins.length > 8192) {
    throw new Error('WebSocket additional origin allowlist is invalid');
  }
  for (const raw of extraOrigins.split(',')) {
    const value = raw.trim();
    if (!value) continue;
    const origin = canonicalOrigin(value);
    if (!origin) throw new Error('WebSocket additional origin must be canonical HTTP(S)');
    known.add(origin);
  }
  return known;
}
function isAllowedOrigin(origin, allowlist) {
  // Native/non-browser clients sometimes omit Origin; authenticated WS
  // routes must still validate their credentials before upgrading.
  if (origin === undefined) return true;
  return typeof origin === 'string' &&
    canonicalOrigin(origin) === origin && allowlist.has(origin);
}
function canAcceptConnection(connected, pending) {
  return Number.isSafeInteger(connected) && connected >= 0 &&
    Number.isSafeInteger(pending) && pending >= 0 &&
    connected + pending < MAX_CONNECTIONS;
}
function outboundSize(value) {
  if (Buffer.isBuffer(value)) return value.length;
  if (typeof value === 'string') return Buffer.byteLength(value, 'utf8');
  if (value instanceof ArrayBuffer) return value.byteLength;
  if (ArrayBuffer.isView(value)) return value.byteLength;
  return MAX_BUFFERED_BYTES + 1;
}
function canBufferMessage(socket, payload) {
  return socket?.readyState === 1 &&
    Number.isFinite(socket.bufferedAmount) &&
    socket.bufferedAmount >= 0 &&
    outboundSize(payload) <= MAX_BUFFERED_BYTES &&
    socket.bufferedAmount + outboundSize(payload) <= MAX_BUFFERED_BYTES;
}
module.exports = {
  MAX_INBOUND_BYTES,MAX_BUFFERED_BYTES,MAX_CONNECTIONS,HEARTBEAT_MS,
  MAX_ASYNC_MESSAGES,canonicalOrigin,allowedOrigins,isAllowedOrigin,
  canAcceptConnection,outboundSize,canBufferMessage
};
