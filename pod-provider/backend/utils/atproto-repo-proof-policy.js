'use strict';

/**
 * Structural boundary for evidence returned by an INTERNAL trusted
 * ActivityPods-managed repository verifier. Not a substitute for the
 * verifier's cryptographic inspection of stored commit, MST, CAR and keys.
 *
 * Consumer must never accept this object from a client/API request.
 */
const CID_RE = /^bafyre[a-z2-7]{53}$/;
const DID_RE = /^did:plc:[a-z2-7]{24}$/;
const TID_RE = /^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/;

function proofError(message) {
  const error = new Error(message);
  error.code = 'ATPROTO_REPO_PROOF_INVALID';
  return error;
}

function requireVerifiedManagedRepoProof({ canonicalAccountId, did, proof }) {
  if (typeof canonicalAccountId !== 'string' || !canonicalAccountId.startsWith('https://') ||
      !DID_RE.test(did || '')) {
    throw proofError('Cannot verify a noncanonical managed account or DID');
  }
  if (!proof || typeof proof !== 'object' ||
      proof.verified !== true ||
      proof.accountId !== canonicalAccountId || proof.did !== did ||
      !CID_RE.test(proof.commitCid || '') ||
      !CID_RE.test(proof.rootCid || '') ||
      !TID_RE.test(proof.rev || '') ||
      (proof.outboxStatus !== 'pending' && proof.outboxStatus !== 'delivered')) {
    throw proofError('Trusted managed repository proof is absent, partial or inconsistent');
  }

  // Strip arbitrary fields from service response. No private keys, CAR bytes
  // or caller-supplied metadata should cross to identitybindings.
  return Object.freeze({
    did,
    accountId: canonicalAccountId,
    commitCid: proof.commitCid,
    rootCid: proof.rootCid,
    rev: proof.rev,
    outboxStatus: proof.outboxStatus
  });
}

module.exports = { requireVerifiedManagedRepoProof };
