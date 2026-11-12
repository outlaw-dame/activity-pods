'use strict';

/**
 * Sidecar responses are transport metadata, never user-authored ActivityPub.
 * The 202 response may be attacker-controlled if a sidecar proxy is
 * misconfigured. Bound allocated memory before decoding or parsing JSON.
 */
const MAX_DURABLE_ACK_BYTES = 4096;

async function readBoundedAcknowledgement(response, maxBytes = MAX_DURABLE_ACK_BYTES) {
  const declared = response.headers?.get?.('content-length');
  if (declared != null && /^\d+$/u.test(declared) && Number(declared) > maxBytes) {
    await response.body?.cancel?.().catch(() => {});
    throw new Error('Sidecar durable acknowledgement exceeds size limit');
  }
  let value;
  if (response.body && typeof response.body.getReader === 'function') {
    const reader = response.body.getReader();
    const pieces = [];
    let bytes = 0;
    try {
      while (true) {
        const { done, value: chunk } = await reader.read();
        if (done) break;
        if (!(chunk instanceof Uint8Array)) {
          throw new Error('Sidecar acknowledgement stream returned invalid bytes');
        }
        bytes += chunk.byteLength;
        if (bytes > maxBytes) {
          await reader.cancel();
          throw new Error('Sidecar durable acknowledgement exceeds size limit');
        }
        pieces.push(Buffer.from(chunk));
      }
    } finally {
      reader.releaseLock();
    }
    try {
      value = JSON.parse(Buffer.concat(pieces, bytes).toString('utf8'));
    } catch {
      throw new Error('Sidecar durable outbox handoff returned an invalid acknowledgement body');
    }
  } else {
    // Used by existing lightweight HTTP stubs; production native fetch always
    // provides a readable body. Still apply an encoded-size limit to stubs.
    try {
      value = await response.json();
      if (Buffer.byteLength(JSON.stringify(value), 'utf8') > maxBytes) {
        throw new RangeError('too large');
      }
    } catch {
      throw new Error('Sidecar durable outbox handoff returned an invalid acknowledgement body');
    }
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Sidecar durable outbox handoff returned an invalid acknowledgement body');
  }
  return value;
}

module.exports = { MAX_DURABLE_ACK_BYTES, readBoundedAcknowledgement };
