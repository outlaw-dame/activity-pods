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
function isCanonicalHttpsWebId(value) {
  if (typeof value !== 'string') return false;
  try {
    const uri = new URL(value);
    // A syntactically valid and normalized HTTPS actor URI must not carry
    // userinfo credentials. Requiring canonical serialization also avoids
    // binding two identities that differ only by URL normalization.
    return uri.protocol === 'https:' &&
      uri.hostname.length > 0 &&
      uri.username === '' && uri.password === '' &&
      uri.href === value;
  } catch {
    return false;
  }
}
/**
 * This create endpoint is exclusively for NEW identities. Importing,
 * migrating, linking or repairing existing WebIDs/DIDs is a different,
 * consent-bound workflow. Reject such fields before any reservation,
 * username registration, signing key or PLC side effect.
 */
const EXISTING_IDENTITY_FIELDS = Object.freeze([
  'accountId', 'canonicalAccountId', 'existingAccountId',
  'webId', 'existingWebId', 'actorId', 'activityPubActorId',
  'did', 'atprotoDid', 'existingDid', 'sourceDid',
  'importDid', 'migration', 'migrate', 'import',
  'linkExisting', 'fromAccountId', 'fromDid'
]);
function requestsExistingIdentity(input) {
  if (!input || typeof input !== 'object') return false;
  const scopes = [
    input,
    input.atproto,
    input.protocols?.atproto,
    input.activitypub,
    input.protocols?.activitypub,
    input.solid,
    input.protocols?.solid
  ];
  return scopes.some(value => value && typeof value === 'object' &&
    (EXISTING_IDENTITY_FIELDS.some(key => Object.prototype.hasOwnProperty.call(value, key)) ||
     value.force === true || value.recover === true || value.repair === true));
}
function assertUnifiedRequest(input) {
  if (requestsExistingIdentity(input)) {
    const error = new Error('UNIFIED_ACCOUNT_NEW_ONLY: use a separate consented migration/linking flow for existing identities');
    error.code = 'UNIFIED_ACCOUNT_NEW_ONLY';
    throw error;
  }
  if (!input || typeof input !== 'object' || Array.isArray(input) || hasExplicitDisable(input) ||
      input?.atproto?.didMethod && !['plc','did:plc'].includes(input.atproto.didMethod)) {
    const error = new Error('UNIFIED_IDENTITY_REQUIRED: WebID, ActivityPub and did:plc are mandatory');
    error.code = 'UNIFIED_IDENTITY_REQUIRED';
    throw error;
  }
  return { ...IDENTITY_PROTOCOLS, didMethod: 'plc' };
}
function assertUnifiedResult(input) {
  const { webId, actorId, did, repoInitialized, identityWebId } =
    input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  if (!isCanonicalHttpsWebId(webId) ||
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
module.exports = Object.freeze({ IDENTITY_PROTOCOLS, assertUnifiedRequest, assertUnifiedResult, isCanonicalHttpsWebId });
