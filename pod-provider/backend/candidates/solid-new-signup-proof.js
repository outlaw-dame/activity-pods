'use strict';

const { isCanonicalHttpsWebId } = require('../utils/unified-identity-policy');
const PLC_DID = /^did:plc:[a-z2-7]{24}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

/**
 * Nonactivated NEW-signup Solid authority verifier. No legacy migration,
 * registration events or repair writes are performed here.
 *
 * The actual SemApps account and Jena identity binding remain authoritative:
 * PostgreSQL records only a digest of successfully observed readiness.
 * All lookups are by exact WebID; never enumerate accounts or scan Pods.
 */
async function verifyNewSignupSolidAuthority({ call, webId, did, operationId } = {}) {
  if (typeof call !== 'function' || !isCanonicalHttpsWebId(webId) ||
      !PLC_DID.test(did || '') ||
      typeof operationId !== 'string' || !UUID.test(operationId)) {
    fail('SOLID_SIGNUP_PROOF_INVALID_INPUT');
  }
  let account, binding, bootstrap;
  try {
    account = await call('auth.account.findByWebId', { webId });
    if (!account || account.disabled === true) {
      fail('SOLID_SIGNUP_PROOF_ACCOUNT_MISSING');
    }
    binding = await call('identitybindings.getByCanonicalAccountId', {
      canonicalAccountId: webId
    });
    // The new account must own the SAME WebID, ActivityPub actor, and
    // did:plc. Do not adopt any preexisting external ATProto identity.
    if (!binding || binding.webId !== webId ||
        binding.activityPubActorId !== webId ||
        binding.atprotoDid !== did ||
        binding.atprotoSource !== 'local' ||
        binding.atprotoManaged !== true) {
      fail('SOLID_SIGNUP_PROOF_IDENTITY_MISMATCH');
    }
    bootstrap = await call('auth.awaitBootstrapComplete', { webId });
    if (bootstrap?.complete !== true || bootstrap.webId !== webId) {
      fail('SOLID_SIGNUP_PROOF_BOOTSTRAP_INCOMPLETE');
    }
  } catch (error) {
    // Keep domain-specific failures, but never leak account data, URLs
    // from errors, or underlying account/registry details in exceptions.
    if (typeof error?.code === 'string' &&
        error.code.startsWith('SOLID_SIGNUP_PROOF_')) throw error;
    fail('SOLID_SIGNUP_PROOF_UNAVAILABLE');
  }
  return Object.freeze({ webId, did, complete: true });
}

module.exports = { verifyNewSignupSolidAuthority };
