'use strict';

/**
 * Structural admission boundary for evidence returned by the *trusted*
 * provider-owned, signed PostgreSQL repository bridge. This must never be
 * applied to a response from an external account-creation request.
 *
 * Only the provider bridge verifies the signed CAR, live DID/handle/commit
 * key, native outbox and canonical account binding. Shape checks alone are
 * NEVER cryptographic proof or a permission to release production signup.
 */
const DID = /^did:plc:[a-z2-7]{24}$/u;
const CID = /^bafyre[a-z2-7]{53}$/u;
const TID = /^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u;

function fail() {
  const error = new Error('Trusted managed repository evidence is absent or inconsistent');
  error.code = 'ATPROTO_REPO_PROOF_INVALID';
  throw error;
}

function canonicalWebId(value) {
  if (typeof value !== 'string' || value.length < 10 || value.length > 2048) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && Boolean(parsed.hostname) &&
      !parsed.username && !parsed.password && !parsed.search && !parsed.hash &&
      parsed.href === value;
  } catch {
    return false;
  }
}

function canonicalOrigin(value) {
  if (typeof value !== 'string' || value.length > 2048) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && Boolean(parsed.hostname) &&
      !parsed.username && !parsed.password && parsed.origin === value &&
      !parsed.search && !parsed.hash && parsed.pathname === '/';
  } catch {
    return false;
  }
}

function requireVerifiedManagedRepoProof({ canonicalAccountId, did, expectedPdsOrigin, proof }) {
  if (!canonicalWebId(canonicalAccountId) || !DID.test(did || '') ||
      !canonicalOrigin(expectedPdsOrigin)) fail();
  if (!proof || typeof proof !== 'object' || Array.isArray(proof) ||
      proof.verified !== true ||
      proof.accountId !== canonicalAccountId || proof.did !== did ||
      proof.pdsOrigin !== expectedPdsOrigin ||
      typeof proof.commitCid !== 'string' || !CID.test(proof.commitCid) ||
      typeof proof.rootCid !== 'string' || !CID.test(proof.rootCid) ||
      proof.commitCid === proof.rootCid ||
      typeof proof.rev !== 'string' || !TID.test(proof.rev) ||
      !['pending', 'delivered'].includes(proof.outboxStatus)) {
    fail();
  }
  // Never project CAR bytes, signing keys, secrets or arbitrary result fields
  // into identitybindings. Preserve only canonical public identifiers.
  return Object.freeze({
    accountId: canonicalAccountId, did,
    pdsOrigin: expectedPdsOrigin,
    commitCid: proof.commitCid, rootCid: proof.rootCid,
    rev: proof.rev, outboxStatus: proof.outboxStatus
  });
}

module.exports = { requireVerifiedManagedRepoProof };
