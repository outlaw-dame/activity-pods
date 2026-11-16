'use strict';

const { isDeepStrictEqual } = require('node:util');
const MAX_OPERATION_BYTES = 16384;
const DID = /^did:plc:[a-z2-7]{24}$/u;

async function cancel(response) {
  try { await response?.body?.cancel(); } catch { /* Already consumed or disconnected. */ }
}

async function readOperation(response) {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('PLC_OPERATION_BODY_MISSING');
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_OPERATION_BYTES) throw new Error('PLC_OPERATION_TOO_LARGE');
      chunks.push(Buffer.from(value));
    }
    return JSON.parse(Buffer.concat(chunks, size).toString('utf8'));
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

/** One bounded attempt. The durable submitter owns scheduling and retry limits. */
async function submitPlcGenesis({ directory, did, signedOp, timeoutMs, fetchImpl = globalThis.fetch }) {
  if (!DID.test(did || '') || signedOp?.type !== 'plc_operation' || signedOp.prev !== null ||
      typeof signedOp.sig !== 'string' || signedOp.sig.length === 0) {
    return { kind: 'failed', error: 'PLC_GENESIS_INVALID' };
  }
  const raw = JSON.stringify(signedOp);
  if (Buffer.byteLength(raw) > MAX_OPERATION_BYTES) return { kind: 'failed', error: 'PLC_GENESIS_TOO_LARGE' };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref?.();
  const url = `${directory}/${did}`;
  try {
    const response = await fetchImpl(url, {
      method: 'POST', redirect: 'error', signal: controller.signal,
      headers: { 'content-type': 'application/json', accept: 'application/json' }, body: raw
    });
    const status = response.status;
    await cancel(response);
    // The reference directory also uses 400 for an already-existing genesis.
    // Neither 400 nor 409 is accepted without exact current-operation readback.
    if (!((status >= 200 && status < 300) || status === 400 || status === 409)) {
      return { kind: status === 429 || status >= 500 ? 'retry' : 'failed', error: `PLC_SUBMIT_HTTP_${status}` };
    }
    // A success or conflict is not evidence that this exact genesis was stored.
    // Check the current operation, including signature, against the durable local
    // operation. Rotation/tombstone/different genesis requires reconciliation.
    const readback = await fetchImpl(`${url}/log/last`, {
      method: 'GET', redirect: 'error', signal: controller.signal,
      headers: { accept: 'application/json' }
    });
    if (readback.status !== 200) {
      const readStatus = readback.status;
      await cancel(readback);
      return { kind: status === 400 && readStatus === 404 ? 'failed' : 'retry', error: `PLC_READBACK_HTTP_${readStatus}` };
    }
    const operation = await readOperation(readback);
    return isDeepStrictEqual(operation, signedOp)
      ? { kind: 'confirmed' }
      : { kind: 'failed', error: 'PLC_GENESIS_READBACK_MISMATCH' };
  } catch {
    // The POST may already have committed. Retain the same operation for bounded
    // retry; never surface a remote body, signature, URL or underlying error.
    return { kind: 'retry', error: controller.signal.aborted ? 'PLC_REQUEST_TIMEOUT' : 'PLC_READBACK_UNAVAILABLE' };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { submitPlcGenesis };
