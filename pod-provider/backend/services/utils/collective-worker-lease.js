'use strict';

const crypto = require('node:crypto');

const WORKER_ID_PATTERN = /^[A-Za-z0-9_-]{8,96}$/u;
const LEASE_TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,128}$/u;
const LEASE_EPOCH_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

function hashLeaseToken(token) {
  if (typeof token !== 'string' || !LEASE_TOKEN_PATTERN.test(token)) return null;
  return crypto.createHash('sha256').update(token).digest('hex');
}

function leaseReference({ workerId, leaseToken, leaseEpoch }) {
  if (typeof workerId !== 'string' || !WORKER_ID_PATTERN.test(workerId) ||
      typeof leaseEpoch !== 'string' || !LEASE_EPOCH_PATTERN.test(leaseEpoch)) {
    return null;
  }
  const hash = hashLeaseToken(leaseToken);
  return hash ? { workerId, leaseEpoch, hash } : null;
}

module.exports = {
  WORKER_ID_PATTERN,
  hashLeaseToken,
  leaseReference
};
