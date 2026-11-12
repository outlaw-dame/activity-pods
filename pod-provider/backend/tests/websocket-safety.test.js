'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  MAX_INBOUND_BYTES, MAX_CONNECTIONS, MAX_BUFFERED_BYTES,
  canonicalOrigin, allowedOrigins, isAllowedOrigin,
  canAcceptConnection, canBufferMessage, outboundSize
} = require('../utils/websocket-safety');

test('WebSocket origin policy accepts configured origins and denies cross-site cookie upgrades', () => {
  const allowed = allowedOrigins(
    'https://pods.example.test/', 'https://paper.example.test/app',
    'https://client.example.test'
  );
  expect(isAllowedOrigin('https://pods.example.test', allowed)).toBe(true);
  expect(isAllowedOrigin('https://paper.example.test', allowed)).toBe(true);
  expect(isAllowedOrigin('https://client.example.test', allowed)).toBe(true);
  expect(isAllowedOrigin('https://attacker.example.test', allowed)).toBe(false);
  expect(isAllowedOrigin('null', allowed)).toBe(false);
  expect(isAllowedOrigin(['https://pods.example.test'], allowed)).toBe(false);
  expect(isAllowedOrigin('https://pods.example.test/', allowed)).toBe(false);
  expect(isAllowedOrigin(undefined, allowed)).toBe(true); // Native clients
  expect(canonicalOrigin('https://pods.example.test/?token=secret')).toBe(null);
  expect(canonicalOrigin('https://user:pass@pods.example.test')).toBe(null);
});

test('malformed and wildcard WebSocket origin configurations fail startup', () => {
  for (const value of [
    '*', 'https://good.example.test/path',
    'https://user:secret@good.example.test', 'null',
    'javascript:alert(1)', 'http://trusted.example.test?session=x'
  ]) {
    expect(() => allowedOrigins('https://pods.example.test', null, value)).toThrow();
  }
  expect(() => allowedOrigins('invalid', null)).toThrow();
  expect(() => allowedOrigins('', '')).toThrow();
});

test('connection count includes concurrent in-flight upgrade handshakes', () => {
  expect(canAcceptConnection(0, 0)).toBe(true);
  expect(canAcceptConnection(MAX_CONNECTIONS - 1, 0)).toBe(true);
  expect(canAcceptConnection(MAX_CONNECTIONS - 1, 1)).toBe(false);
  expect(canAcceptConnection(MAX_CONNECTIONS, 0)).toBe(false);
  expect(canAcceptConnection(0, MAX_CONNECTIONS)).toBe(false);
  expect(canAcceptConnection(-1, 0)).toBe(false);
});

test('outbound queued bytes and unknown payloads have a hard memory ceiling', () => {
  const socket = { readyState: 1, bufferedAmount: 0 };
  expect(canBufferMessage(socket, 'hello')).toBe(true);
  expect(outboundSize('é')).toBe(2);
  expect(canBufferMessage(socket, Buffer.alloc(MAX_BUFFERED_BYTES))).toBe(true);
  expect(canBufferMessage(socket, Buffer.alloc(MAX_BUFFERED_BYTES + 1))).toBe(false);
  expect(canBufferMessage(socket, {})).toBe(false);
  socket.bufferedAmount = MAX_BUFFERED_BYTES - 1;
  expect(canBufferMessage(socket, Buffer.alloc(2))).toBe(false);
  socket.readyState = 3;
  expect(canBufferMessage(socket, 'small')).toBe(false);
  expect(MAX_INBOUND_BYTES).toBe(262144);
});

test('gateway reuses one ws server, disconnects idle clients, and never logs the query URL', () => {
  const source = fs.readFileSync(path.join(__dirname, '../mixins/websocket.js'), 'utf8');
  expect(source).toContain('perMessageDeflate: false');
  expect(source).toContain('maxPayload: MAX_INBOUND_BYTES');
  expect(source).toContain('if (ws.__apodsHeartbeatAlive === false)');
  expect(source).toContain('this.server?.off(\'upgrade\', this.upgradeHandler)');
  expect(source).toContain('this.connectionIndexes.set(last, index)');
  expect(source).toContain('if (inflightMessages >= MAX_ASYNC_MESSAGES)');
  expect(source).not.toContain('this.connections = this.connections.filter(');
  expect(source).not.toContain('New WebSocket registered with URI');
});
