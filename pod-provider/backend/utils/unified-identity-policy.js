'use strict';

/**
 * Canonical NEW-account provisioning policy for Paper/ActivityPods.
 * A profile may expose optional protocols, but a created account may NOT
 * silently omit any of these three mandatory identity components.
 */
const IDENTITY_PROTOCOLS = Object.freeze({
  solid: true,
  activitypub: true,
  atproto: true
});
function hasExplicitDisable(input) {
  // The internal service may be called directly, bypassing the HTTP adapter's
  // normalization. Enforce the same opt-out restriction on either shape.
  return ['solid', 'activitypub', 'atproto'].some(kind =>
    input?.[kind] === false ||
    input?.[kind]?.enabled === false ||
    input?.protocols?.[kind] === false ||
    input?.protocols?.[kind]?.enabled === false
  );
}
function assertUnifiedRequest(input) {
  if (!input || typeof input !== 'object' || hasExplicitDisable(input) ||
      input?.atproto?.didMethod && !['plc','did:plc'].includes(input.atproto.didMethod)) {
    const error = new Error('UNIFIED_IDENTITY_REQUIRED: WebID, ActivityPub and did:plc are mandatory');
    error.code = 'UNIFIED_IDENTITY_REQUIRED';
    throw error;
  }
  return { ...IDENTITY_PROTOCOLS, didMethod: 'plc' };
}
function assertUnifiedResult({ webId, actorId, did, repoInitialized, identityWebId }) {
  if (typeof webId !== 'string' || !webId.startsWith('https://') ||
      typeof actorId !== 'string' || actorId !== webId ||
      typeof did !== 'string' || !/^did:plc:[a-z2-7]{24}$/.test(did) ||
      repoInitialized !== true ||
      identityWebId != null && identityWebId !== webId) {
    const error = new Error('UNIFIED_IDENTITY_INCOMPLETE: account has not completed AP/WebID and ATProto provisioning');
    error.code = 'UNIFIED_IDENTITY_INCOMPLETE';
    throw error;
  }
  return true;
}
module.exports = Object.freeze({ IDENTITY_PROTOCOLS, assertUnifiedRequest, assertUnifiedResult });
