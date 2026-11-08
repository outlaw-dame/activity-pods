'use strict';

/**
 * G1 collective identity boundary: validation of a provider-sourced *public
 * projection*, not an identity issuer, DID resolver or permission checker.
 *
 * Callers MUST obtain the input from an authenticated, provider-authoritative
 * record and MUST authorize access before invoking this function. The validator
 * never treats caller-supplied data as proof of Group ownership or DID control.
 *
 * Keep this module separate from legacy groups.js and account identitybindings.
 */

class CollectiveIdentityError extends Error {
  constructor(code) {
    super(code);
    this.name = 'CollectiveIdentityError';
    this.code = code;
  }
}

const ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_-]{11,127}$/;
const DID_PLC_PATTERN = /^did:plc:[a-z2-7]{24}$/;

function fail(code) {
  throw new CollectiveIdentityError(code);
}

/**
 * Exact, unambiguous, publicly dereferenceable HTTPS URL. Reject userinfo,
 * query, fragments, encoding ambiguity, path backslashes and normalization.
 * Reject even syntactically valid URLs that differ from their serialized form.
 */
function publicUrl(value, code) {
  if (typeof value !== 'string' || value.length < 9 || value.length > 2048 ||
      /[\u0000-\u0020\u007f\\]/.test(value)) fail(code);
  let url;
  try {
    url = new URL(value);
  } catch {
    fail(code);
  }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password ||
      url.search || url.hash || url.href !== value || url.pathname === '/' ||
      /%(?:2f|5c|2e|00)/i.test(value)) fail(code);
  return url;
}

function assertSameProvider(url, provider) {
  if (url.origin !== provider.origin) fail('GROUP_CROSS_PROVIDER_URI');
}

function nonEmpty(value, code, max = 256) {
  if (typeof value !== 'string' || value.length === 0 || value.length > max ||
      value !== value.trim() || /[\u0000-\u001f\u007f]/.test(value)) fail(code);
  return value;
}

/**
 * Validate a typed Group projection and return only explicitly approved public
 * fields. No private membership, governance policy, signer secret or raw record
 * properties are copied to the output. This MUST NOT be used to turn untrusted
 * app-supplied JSON into a group identity.
 */
function validatePublicCollectiveActor(record, { providerOrigin, expectedActorUri } = {}) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) fail('GROUP_NOT_FOUND');
  if (typeof providerOrigin !== 'string' || providerOrigin.length > 256 ||
      /[\\u0000-\\u0020\\u007f\\\\]/.test(providerOrigin)) fail('GROUP_INVALID_PROVIDER');
  let provider;
  try {
    provider = new URL(providerOrigin);
  } catch {
    fail('GROUP_INVALID_PROVIDER');
  }
  if (provider.protocol !== 'https:' || !provider.hostname || provider.origin !== providerOrigin ||
      provider.username || provider.password || provider.search || provider.hash) fail('GROUP_INVALID_PROVIDER');

  const canonicalGroupId = nonEmpty(record.canonicalGroupId, 'GROUP_INVALID_ID', 128);
  if (!ID_PATTERN.test(canonicalGroupId)) fail('GROUP_INVALID_ID');
  if (record.actorType !== 'Group') fail('GROUP_TYPE_MISMATCH');
  if (record.status !== 'active') fail('GROUP_NOT_ACTIVE');
  if (!Number.isSafeInteger(record.identityRevision) || record.identityRevision < 1 ||
      !Number.isSafeInteger(record.policyRevision) || record.policyRevision < 1) {
    fail('GROUP_INVALID_REVISION');
  }

  const actor = publicUrl(record.actorUri, 'GROUP_INVALID_ACTOR_URI');
  assertSameProvider(actor, provider);
  if (typeof expectedActorUri !== 'string' || actor.href !== expectedActorUri) {
    fail('GROUP_ACTOR_URI_MISMATCH');
  }
  const inbox = publicUrl(record.inboxUri, 'GROUP_INVALID_INBOX_URI');
  const outbox = publicUrl(record.outboxUri, 'GROUP_INVALID_OUTBOX_URI');
  const followers = publicUrl(record.followersUri, 'GROUP_INVALID_FOLLOWERS_URI');
  for (const endpoint of [inbox, outbox, followers]) {
    assertSameProvider(endpoint, provider);
  }
  if (new Set([actor.href, inbox.href, outbox.href, followers.href]).size !== 4) {
    fail('GROUP_DUPLICATE_ENDPOINT');
  }
  // Do not accept an arbitrary key owner, or a key belonging to another actor.
  // This is only URI consistency, NOT cryptographic proof of a key binding.
  if (typeof record.publicKeyId !== 'string' ||
      !record.publicKeyId.startsWith(actor.href + '#') ||
      !/^[a-zA-Z0-9_-]{1,64}$/.test(record.publicKeyId.slice(actor.href.length + 1))) {
    fail('GROUP_INVALID_KEY_ID');
  }

  return Object.freeze({
    canonicalGroupId,
    actorType: 'Group',
    actorUri: actor.href,
    displayName: nonEmpty(record.displayName, 'GROUP_INVALID_DISPLAY_NAME', 180),
    preferredUsername: nonEmpty(record.preferredUsername, 'GROUP_INVALID_USERNAME', 128),
    inboxUri: inbox.href,
    outboxUri: outbox.href,
    followersUri: followers.href,
    publicKeyId: record.publicKeyId,
    identityRevision: record.identityRevision,
    policyRevision: record.policyRevision
  });
}

/**
 * Syntax screening only; never treat this as DID registration/control proof.
 * A hosted group DID MUST be independently verified with DID resolution and
 * signed PLC genesis or equivalent method-specific control proof.
 */
function validateManagedGroupDidSyntax(did) {
  if (typeof did !== 'string' || !DID_PLC_PATTERN.test(did)) fail('GROUP_INVALID_DID');
  return did;
}

module.exports = {
  CollectiveIdentityError,
  validatePublicCollectiveActor,
  validateManagedGroupDidSyntax
};
