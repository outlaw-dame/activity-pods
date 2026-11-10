'use strict';

// Shared, exact operation fingerprint; app and provider must never independently
// hand-roll a different canonicalization for the same consented Group request.
const crypto = require('node:crypto');

function reserveFingerprint(principal, app, idempotencyKey, displayName) {
  return crypto.createHash('sha256').update(JSON.stringify([
    principal, app, idempotencyKey, displayName
  ])).digest('hex');
}

module.exports = { reserveFingerprint };
