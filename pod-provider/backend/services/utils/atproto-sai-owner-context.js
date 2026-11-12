'use strict';

const crypto = require('node:crypto');

// Moleculer propagates ctx.requestID and a *copy* of ctx.meta to child
// actions. It does not retain a parentCtx reference on the child Context.
// An unpredictable nonce checked against a provider-local authorization
// record is therefore required; metadata by itself is not authority.
const PROOF_KEY = 'apodsNativeSaiOwnerProof';
const MAX_IN_FLIGHT = 4096;
const MAX_LIFETIME_NS = 120_000_000_000n;
const proofs = new Map();

function authorizeOwnerSaiAction(ctx, { owner, app }) {
  if (!ctx || typeof ctx.requestID !== 'string' ||
      !ctx.requestID || ctx.requestID.length > 256 ||
      typeof owner !== 'string' || typeof app !== 'string' ||
      !owner.startsWith('https://') || !app.startsWith('https://') ||
      !ctx.meta || ctx.meta.webId !== owner || ctx.meta.impersonatedUser ||
      Object.prototype.hasOwnProperty.call(ctx.meta, PROOF_KEY)) {
    const error = new Error('Only the authenticated Pod owner may authorize this SAI change');
    error.code = 'ATPROTO_SAI_OWNER_CONTEXT_INVALID';
    throw error;
  }
  if (proofs.size >= MAX_IN_FLIGHT) {
    // A hung provider request cannot grow the map indefinitely. Only
    // when saturated, discard expired entries before refusing new work.
    const now = process.hrtime.bigint();
    for (const [key, entry] of proofs) {
      if (now >= entry.until) proofs.delete(key);
    }
    if (proofs.size >= MAX_IN_FLIGHT) {
      const error = new Error('Too many in-flight SAI authorizations');
      error.code = 'ATPROTO_SAI_OWNER_CONTEXT_BUSY';
      throw error;
    }
  }

  const nonce = crypto.randomBytes(32).toString('base64url');
  const entry = {
    owner, app, requestID: ctx.requestID,
    until: process.hrtime.bigint() + MAX_LIFETIME_NS
  };
  proofs.set(nonce, entry);
  ctx.meta[PROOF_KEY] = nonce;
  return () => {
    proofs.delete(nonce);
    if (ctx.meta[PROOF_KEY] === nonce) delete ctx.meta[PROOF_KEY];
  };
}

function hasAuthorizedOwnerParent(ctx, { owner, app }) {
  const nonce = ctx?.meta?.[PROOF_KEY];
  if (typeof nonce !== 'string' || nonce.length !== 43) return false;
  const entry = proofs.get(nonce);
  if (!entry) return false;
  if (process.hrtime.bigint() >= entry.until) {
    proofs.delete(nonce);
    return false;
  }
  return entry.owner === owner && entry.app === app &&
    entry.requestID === ctx.requestID;
}


async function authorizeOwnerSaiActionForBroker(ctx, scope) {
  if (process.env.APODS_ATPROTO_SAI_OWNER_DISTRIBUTED_ENABLED !== 'true') {
    return authorizeOwnerSaiAction(ctx, scope);
  }
  // No Redis connection is opened when the feature is disabled.
  return require('./atproto-sai-distributed-owner-runtime').issueDistributedOwnerProof(ctx, scope);
}

async function hasAuthorizedOwnerParentForBroker(ctx, scope) {
  if (process.env.APODS_ATPROTO_SAI_OWNER_DISTRIBUTED_ENABLED !== 'true') {
    return hasAuthorizedOwnerParent(ctx, scope);
  }
  return require('./atproto-sai-distributed-owner-runtime').verifyDistributedOwnerProof(ctx, scope);
}

module.exports = {
  authorizeOwnerSaiAction, hasAuthorizedOwnerParent,
  authorizeOwnerSaiActionForBroker, hasAuthorizedOwnerParentForBroker
};
