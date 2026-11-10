'use strict';

const fs = require('fs');
const path = require('path');
const { createHash } = require('crypto');

const EXPECTED_VERSION = '1.1.4';
const MARKER = 'activitypods-activitypub-inbox-actor-id-v7';
const CHILD_META_UNSUPPORTED_MARKER = 'activitypods-activitypub-inbox-actor-id-v6';
const RAW_ACTOR_UNSUPPORTED_MARKER = 'activitypods-activitypub-inbox-actor-id-v5';
const SINGLETON_UNSUPPORTED_MARKER = 'activitypods-activitypub-inbox-actor-id-v4';
const PREVIOUS_MARKER = 'activitypods-activitypub-inbox-actor-id-v3';
const OLDER_MARKER = 'activitypods-activitypub-inbox-actor-id-v2';
const LEGACY_MARKER = 'activitypods-activitypub-inbox-actor-id-v1';
const PRISTINE_HASH = '99386b74357a63b70b025b210925dc031c614315b147b4f91bc76a911f38fbbc';
const LEGACY_PATCHED_HASH = 'a141c4fc22e34d0cddb323c36a491594649f8072724618d9ffc7e32fcad88057';
const OLDER_PATCHED_HASH = '8c349b9d18ea11f996e22860025dd9a78f01b75bf66cb46745062cf6203f10b3';
const PREVIOUS_PATCHED_HASH = 'fef56adcc165c4d990e255afdab93538a2d96363bc12d6aba95b673bf6136290';
const SINGLETON_UNSUPPORTED_PATCHED_HASH = '8d40d956a047174c4a15b2103a90a18afaad2a03cbae066717a29d60f460e310';
const RAW_ACTOR_UNSUPPORTED_PATCHED_HASH = '62742f613905853192ed8bf16268392b159dfa7d4b60aebc27d28921d89d9a17';
const CHILD_META_UNSUPPORTED_PATCHED_HASH = 'bcb616f782453ebea7ee5955185495b8b863bbdfd7a3316a9ec78d47b5aa66b6';
const PATCHED_HASH = 'a8bdca4d3534b4f842f828552eef4d2761f60e2684f0a098f77ebb3037a3d4dc';
const API_MARKER = 'activitypods-activitypub-inbox-raw-actor-meta-v3';
const PREVIOUS_API_MARKER = 'activitypods-activitypub-inbox-raw-actor-meta-v2';
const OLDER_API_MARKER = 'activitypods-activitypub-inbox-raw-actor-meta-v1';
const PRISTINE_API_HASH = 'cd259b9ace2bf4ad822197d5cfcbc063f287076bc7fcf0ecdaaef6c4853952d6';
const OLDER_PATCHED_API_HASH = '190950cf538b69a684c77be7fd5634d93829e460a708ec809098ed659e978ff1';
const PREVIOUS_PATCHED_API_HASH = '73c65a93391b0eb6b0a98de21143957db72ab546a104aa9b23ef455f893690bb';
const PATCHED_API_HASH = 'eb678da280cf54b1f455b6f1c688c8ccaf99fcfce2f89e184ce70235f32255a8';

function sha256(source) {
  return createHash('sha256').update(source).digest('hex');
}

function requireHash(source, expected, label) {
  const actual = sha256(source);
  if (expected && actual !== expected) {
    throw new Error(`Pinned SemApps ${label} hash mismatch: expected ${expected}, found ${actual}`);
  }
}

function replaceOnce(source, search, replacement, label) {
  const first = source.indexOf(search);
  if (first < 0 || source.indexOf(search, first + search.length) >= 0) {
    throw new Error(`Expected exactly one pinned SemApps ${label}`);
  }
  return source.replace(search, replacement);
}

function addSingletonActorArraySupport(source) {
  return replaceOnce(
    source,
    `  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;`,
    `  if (Array.isArray(value)) return value.length === 1 ? activityActorId(value[0]) : null;
  if (!value || typeof value !== 'object') return null;`,
    'singleton actor array normalization'
  );
}

function addRawActorBinding(source) {
  let upgraded = replaceOnce(
    source,
    RAW_ACTOR_UNSUPPORTED_MARKER,
    CHILD_META_UNSUPPORTED_MARKER,
    'raw-actor-unsupported marker'
  );
  upgraded = replaceOnce(
    upgraded,
    `  return id || atId;
} // ${CHILD_META_UNSUPPORTED_MARKER}`,
    `  return id || atId;
}

function rawActivityActorId(rawBody) {
  if (typeof rawBody !== 'string' && !Buffer.isBuffer(rawBody)) return null;
  try {
    const parsed = JSON.parse(Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    return activityActorId(parsed.actor);
  } catch {
    return null;
  }
} // ${CHILD_META_UNSUPPORTED_MARKER}`,
    'signed raw activity actor helper'
  );
  upgraded = replaceOnce(
    upgraded,
    `      const activityActorUri = activityActorId(activity.actor);
      if (activityActorUri !== authenticatedActorUri) {
        this.logger.warn('Rejected ActivityPub inbox actor/signature mismatch', { authenticatedActorUri, activityActorUri });
        throw new E.UnAuthorizedError('INVALID_ACTOR', 'Activity actor is not the same as the posting actor');
      }`,
    `      const parsedActivityActorUri = activityActorId(activity.actor);
      const rawActivityActorUri = rawActivityActorId(ctx.meta.rawBody);
      if (parsedActivityActorUri && rawActivityActorUri && parsedActivityActorUri !== rawActivityActorUri) {
        this.logger.warn('Rejected ActivityPub inbox raw/action actor mismatch', {
          authenticatedActorUri,
          parsedActivityActorUri,
          rawActivityActorUri
        });
        throw new E.UnAuthorizedError('INVALID_ACTOR', 'Activity actor changed during request processing');
      }
      const activityActorUri = parsedActivityActorUri || rawActivityActorUri;
      if (activityActorUri !== authenticatedActorUri) {
        this.logger.warn('Rejected ActivityPub inbox actor/signature mismatch', { authenticatedActorUri, activityActorUri });
        throw new E.UnAuthorizedError('INVALID_ACTOR', 'Activity actor is not the same as the posting actor');
      }
      if (!parsedActivityActorUri) activity.actor = rawActivityActorUri;`,
    'signed raw/action actor binding'
  );
  return addChildMetaRawActorBinding(upgraded);
}

function addChildMetaRawActorBinding(source) {
  let upgraded = replaceOnce(source, CHILD_META_UNSUPPORTED_MARKER, MARKER, 'child-meta-unsupported marker');
  upgraded = replaceOnce(
    upgraded,
    '      const rawActivityActorUri = rawActivityActorId(ctx.meta.rawBody);',
    `      const directRawActivityActorUri = rawActivityActorId(ctx.meta.rawBody);
      const capturedRawActivityActorUri = activityActorId(ctx.meta.signedRawActivityActorUri);
      if (directRawActivityActorUri && capturedRawActivityActorUri && directRawActivityActorUri !== capturedRawActivityActorUri) {
        this.logger.warn('Rejected ActivityPub inbox raw actor metadata mismatch', {
          authenticatedActorUri,
          directRawActivityActorUri,
          capturedRawActivityActorUri
        });
        throw new E.UnAuthorizedError('INVALID_ACTOR', 'Signed activity actor metadata changed during request processing');
      }
      const rawActivityActorUri = directRawActivityActorUri || capturedRawActivityActorUri;`,
    'signed raw actor child metadata binding'
  );
  return upgraded;
}

function patchInbox(source) {
  if (source.includes(MARKER)) {
    requireHash(source, PATCHED_HASH, 'patched ActivityPub inbox source');
    return { source, changed: false };
  }

  if (source.includes(CHILD_META_UNSUPPORTED_MARKER)) {
    requireHash(source, CHILD_META_UNSUPPORTED_PATCHED_HASH, 'child-meta-unsupported patched ActivityPub inbox source');
    const upgraded = addChildMetaRawActorBinding(source);
    requireHash(upgraded, PATCHED_HASH, 'patched ActivityPub inbox source');
    return { source: upgraded, changed: true };
  }

  if (source.includes(RAW_ACTOR_UNSUPPORTED_MARKER)) {
    requireHash(source, RAW_ACTOR_UNSUPPORTED_PATCHED_HASH, 'raw-actor-unsupported patched ActivityPub inbox source');
    const upgraded = addRawActorBinding(source);
    requireHash(upgraded, PATCHED_HASH, 'patched ActivityPub inbox source');
    return { source: upgraded, changed: true };
  }

  if (source.includes(SINGLETON_UNSUPPORTED_MARKER)) {
    requireHash(source, SINGLETON_UNSUPPORTED_PATCHED_HASH, 'singleton-unsupported patched ActivityPub inbox source');
    let upgraded = replaceOnce(
      source,
      SINGLETON_UNSUPPORTED_MARKER,
      RAW_ACTOR_UNSUPPORTED_MARKER,
      'singleton-unsupported inbox actor identifier marker'
    );
    upgraded = addSingletonActorArraySupport(upgraded);
    upgraded = addRawActorBinding(upgraded);
    requireHash(upgraded, PATCHED_HASH, 'patched ActivityPub inbox source');
    return { source: upgraded, changed: true };
  }

  if (source.includes(PREVIOUS_MARKER)) {
    requireHash(source, PREVIOUS_PATCHED_HASH, 'previous patched ActivityPub inbox source');
    let upgraded = replaceOnce(source, PREVIOUS_MARKER, RAW_ACTOR_UNSUPPORTED_MARKER, 'previous inbox actor identifier marker');
    upgraded = replaceOnce(
      upgraded,
      `      if (activityActorId(activity.actor) !== authenticatedActorUri) {
        throw new E.UnAuthorizedError('INVALID_ACTOR', 'Activity actor is not the same as the posting actor');
      }`,
      `      const activityActorUri = activityActorId(activity.actor);
      if (activityActorUri !== authenticatedActorUri) {
        this.logger.warn('Rejected ActivityPub inbox actor/signature mismatch', { authenticatedActorUri, activityActorUri });
        throw new E.UnAuthorizedError('INVALID_ACTOR', 'Activity actor is not the same as the posting actor');
      }`,
      'actor mismatch diagnostics'
    );
    upgraded = addSingletonActorArraySupport(upgraded);
    upgraded = addRawActorBinding(upgraded);
    requireHash(upgraded, PATCHED_HASH, 'patched ActivityPub inbox source');
    return { source: upgraded, changed: true };
  }

  if (source.includes(OLDER_MARKER)) {
    requireHash(source, OLDER_PATCHED_HASH, 'older patched ActivityPub inbox source');
    let upgraded = replaceOnce(source, OLDER_MARKER, RAW_ACTOR_UNSUPPORTED_MARKER, 'older inbox actor identifier marker');
    upgraded = replaceOnce(
      upgraded,
      '      const authenticatedActorUri = ctx.meta.webId;',
      '      const authenticatedActorUri = ctx.meta.httpSignatureActorUri || ctx.meta.webId;',
      'request-scoped HTTP signature principal'
    );
    upgraded = replaceOnce(
      upgraded,
      `      if (activityActorId(activity.actor) !== authenticatedActorUri) {
        throw new E.UnAuthorizedError('INVALID_ACTOR', 'Activity actor is not the same as the posting actor');
      }`,
      `      const activityActorUri = activityActorId(activity.actor);
      if (activityActorUri !== authenticatedActorUri) {
        this.logger.warn('Rejected ActivityPub inbox actor/signature mismatch', { authenticatedActorUri, activityActorUri });
        throw new E.UnAuthorizedError('INVALID_ACTOR', 'Activity actor is not the same as the posting actor');
      }`,
      'actor mismatch diagnostics'
    );
    upgraded = addSingletonActorArraySupport(upgraded);
    upgraded = addRawActorBinding(upgraded);
    requireHash(upgraded, PATCHED_HASH, 'patched ActivityPub inbox source');
    return { source: upgraded, changed: true };
  }

  if (source.includes(LEGACY_MARKER)) {
    requireHash(source, LEGACY_PATCHED_HASH, 'legacy patched ActivityPub inbox source');
    let upgraded = replaceOnce(source, LEGACY_MARKER, RAW_ACTOR_UNSUPPORTED_MARKER, 'legacy inbox actor identifier marker');
    upgraded = replaceOnce(
      upgraded,
      '      const { collectionUri, ...activity } = ctx.params;',
      `      const { collectionUri, ...activity } = ctx.params;
      const authenticatedActorUri = ctx.meta.httpSignatureActorUri || ctx.meta.webId;`,
      'authenticated actor snapshot'
    );
    upgraded = replaceOnce(
      upgraded,
      '      if (activityActorId(activity.actor) !== ctx.meta.webId) {',
      `      const activityActorUri = activityActorId(activity.actor);
      if (activityActorUri !== authenticatedActorUri) {
        this.logger.warn('Rejected ActivityPub inbox actor/signature mismatch', { authenticatedActorUri, activityActorUri });`,
      'immutable authenticated actor comparison'
    );
    upgraded = addSingletonActorArraySupport(upgraded);
    upgraded = addRawActorBinding(upgraded);
    requireHash(upgraded, PATCHED_HASH, 'patched ActivityPub inbox source');
    return { source: upgraded, changed: true };
  }

  requireHash(source, PRISTINE_HASH, 'pristine ActivityPub inbox source');
  let patched = replaceOnce(
    source,
    'const AwaitActivityMixin = require(\'../../../mixins/await-activity\');',
    `const AwaitActivityMixin = require('../../../mixins/await-activity');

function activityActorId(value) {
  if (typeof value === 'string' && value.length > 0) return value;
  if (Array.isArray(value)) return value.length === 1 ? activityActorId(value[0]) : null;
  if (!value || typeof value !== 'object') return null;
  const id = typeof value.id === 'string' && value.id.length > 0 ? value.id : null;
  const atId = typeof value['@id'] === 'string' && value['@id'].length > 0 ? value['@id'] : null;
  if (id && atId && id !== atId) return null;
  return id || atId;
}

function rawActivityActorId(rawBody) {
  if (typeof rawBody !== 'string' && !Buffer.isBuffer(rawBody)) return null;
  try {
    const parsed = JSON.parse(Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    return activityActorId(parsed.actor);
  } catch {
    return null;
  }
} // ${MARKER}`,
    'inbox actor identifier helper'
  );
  patched = replaceOnce(
    patched,
    '      const { collectionUri, ...activity } = ctx.params;',
    `      const { collectionUri, ...activity } = ctx.params;
      const authenticatedActorUri = ctx.meta.httpSignatureActorUri || ctx.meta.webId;`,
    'authenticated actor snapshot'
  );
  patched = replaceOnce(
    patched,
    `      if (activity.actor !== ctx.meta.webId) {
        throw new E.UnAuthorizedError('INVALID_ACTOR', 'Activity actor is not the same as the posting actor');
      }`,
    `      const parsedActivityActorUri = activityActorId(activity.actor);
      const directRawActivityActorUri = rawActivityActorId(ctx.meta.rawBody);
      const capturedRawActivityActorUri = activityActorId(ctx.meta.signedRawActivityActorUri);
      if (directRawActivityActorUri && capturedRawActivityActorUri && directRawActivityActorUri !== capturedRawActivityActorUri) {
        this.logger.warn('Rejected ActivityPub inbox raw actor metadata mismatch', {
          authenticatedActorUri,
          directRawActivityActorUri,
          capturedRawActivityActorUri
        });
        throw new E.UnAuthorizedError('INVALID_ACTOR', 'Signed activity actor metadata changed during request processing');
      }
      const rawActivityActorUri = directRawActivityActorUri || capturedRawActivityActorUri;
      if (parsedActivityActorUri && rawActivityActorUri && parsedActivityActorUri !== rawActivityActorUri) {
        this.logger.warn('Rejected ActivityPub inbox raw/action actor mismatch', {
          authenticatedActorUri,
          parsedActivityActorUri,
          rawActivityActorUri
        });
        throw new E.UnAuthorizedError('INVALID_ACTOR', 'Activity actor changed during request processing');
      }
      const activityActorUri = parsedActivityActorUri || rawActivityActorUri;
      if (activityActorUri !== authenticatedActorUri) {
        this.logger.warn('Rejected ActivityPub inbox actor/signature mismatch', { authenticatedActorUri, activityActorUri });
        throw new E.UnAuthorizedError('INVALID_ACTOR', 'Activity actor is not the same as the posting actor');
      }
      if (!parsedActivityActorUri) activity.actor = rawActivityActorUri;`,
    'inbox authenticated actor comparison'
  );
  requireHash(patched, PATCHED_HASH, 'patched ActivityPub inbox source');
  return { source: patched, changed: true };
}

function addActivityPubContentTypeProfileSupport(source) {
  let upgraded = replaceOnce(source, OLDER_API_MARKER, PREVIOUS_API_MARKER, 'older API marker');
  upgraded = replaceOnce(
    upgraded,
    `} // ${PREVIOUS_API_MARKER}`,
    `} // ${PREVIOUS_API_MARKER}

function normalizeActivityPubContentType(req, res, next) {
  const contentType = req.$ctx.meta.headers?.['content-type'];
  if (typeof contentType === 'string') {
    const mediaType = contentType.split(';', 1)[0].trim().toLowerCase();
    if (mediaType === 'application/activity+json' || mediaType === 'application/ld+json') {
      // originalHeaders retains the exact signed value captured by parseHeader.
      req.$ctx.meta.headers['content-type'] = mediaType;
    }
  }
  next();
}`,
    'ActivityPub Content-Type profile normalizer'
  );
  upgraded = replaceOnce(
    upgraded,
    `        parseUrl,
        parseHeader,
        negotiateContentType,`,
    `        parseUrl,
        parseHeader,
        normalizeActivityPubContentType,
        negotiateContentType,`,
    'ActivityPub Content-Type profile middleware registration'
  );
  return upgraded;
}

function addActivityPubAcceptProfileSupport(source) {
  let upgraded = replaceOnce(source, PREVIOUS_API_MARKER, API_MARKER, 'previous API marker');
  upgraded = replaceOnce(
    upgraded,
    `  next();
}

const ApiService = {`,
    `  next();
}

function normalizeActivityPubAccept(req, res, next) {
  const accept = req.$ctx.meta.headers?.accept;
  if (typeof accept === 'string') {
    const normalized = accept.trim();
    if (/^application\\/activity\\+json$/i.test(normalized) ||
      /^application\\/ld\\+json\\s*;\\s*profile\\s*=\\s*"https:\\/\\/www\\.w3\\.org\\/ns\\/activitystreams"\\s*$/i.test(normalized)) {
      // originalHeaders retains the exact value used by signature verification.
      req.$ctx.meta.headers.accept = normalized.toLowerCase().startsWith('application/activity+json')
        ? 'application/activity+json'
        : 'application/ld+json';
    }
  }
  next();
}

const ApiService = {`,
    'ActivityPub Accept profile normalizer'
  );
  upgraded = replaceOnce(
    upgraded,
    `        normalizeActivityPubContentType,
        negotiateContentType,
        negotiateAccept,`,
    `        normalizeActivityPubContentType,
        negotiateContentType,
        normalizeActivityPubAccept,
        negotiateAccept,`,
    'ActivityPub Accept profile middleware registration'
  );
  return upgraded;
}

function patchApi(source) {
  if (source.includes(API_MARKER)) {
    requireHash(source, PATCHED_API_HASH, 'patched ActivityPub API source');
    return { source, changed: false };
  }
  if (source.includes(PREVIOUS_API_MARKER)) {
    requireHash(source, PREVIOUS_PATCHED_API_HASH, 'previous patched ActivityPub API source');
    const upgraded = addActivityPubAcceptProfileSupport(source);
    requireHash(upgraded, PATCHED_API_HASH, 'patched ActivityPub API source');
    return { source: upgraded, changed: true };
  }
  if (source.includes(OLDER_API_MARKER)) {
    requireHash(source, OLDER_PATCHED_API_HASH, 'older patched ActivityPub API source');
    const contentTypeUpgraded = addActivityPubContentTypeProfileSupport(source);
    requireHash(contentTypeUpgraded, PREVIOUS_PATCHED_API_HASH, 'previous patched ActivityPub API source');
    const upgraded = addActivityPubAcceptProfileSupport(contentTypeUpgraded);
    requireHash(upgraded, PATCHED_API_HASH, 'patched ActivityPub API source');
    return { source: upgraded, changed: true };
  }
  requireHash(source, PRISTINE_API_HASH, 'pristine ActivityPub API source');
  let patched = replaceOnce(
    source,
    `const { FULL_ACTOR_TYPES } = require('../../../constants');`,
    `const { FULL_ACTOR_TYPES } = require('../../../constants');

function signedRawActivityActorId(rawBody) {
  if (typeof rawBody !== 'string' && !Buffer.isBuffer(rawBody)) return null;
  try {
    const document = JSON.parse(Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody);
    const actor = document && typeof document === 'object' && !Array.isArray(document) ? document.actor : null;
    if (typeof actor === 'string' && actor.length > 0) return actor;
    if (Array.isArray(actor)) return actor.length === 1 ? signedRawActivityActorId(JSON.stringify({ actor: actor[0] })) : null;
    if (!actor || typeof actor !== 'object') return null;
    const id = typeof actor.id === 'string' && actor.id.length > 0 ? actor.id : null;
    const atId = typeof actor['@id'] === 'string' && actor['@id'].length > 0 ? actor['@id'] : null;
    return id && atId && id !== atId ? null : id || atId;
  } catch {
    return null;
  }
} // ${OLDER_API_MARKER}`,
    'API signed raw actor helper'
  );
  patched = replaceOnce(
    patched,
    `      await ctx.call('activitypub.inbox.post', {
        collectionUri: urlJoin(origin, requestUrl),
        ...activity
      });`,
    `      const signedRawActivityActorUri = signedRawActivityActorId(ctx.meta.rawBody);
      await ctx.call('activitypub.inbox.post', {
        collectionUri: urlJoin(origin, requestUrl),
        ...activity
      }, {
        meta: { ...ctx.meta, signedRawActivityActorUri }
      });`,
    'API inbox raw actor metadata propagation'
  );
  const contentTypeUpgraded = addActivityPubContentTypeProfileSupport(patched);
  const upgraded = addActivityPubAcceptProfileSupport(contentTypeUpgraded);
  requireHash(upgraded, PATCHED_API_HASH, 'patched ActivityPub API source');
  return { source: upgraded, changed: true };
}

function applyPatch(root = path.dirname(require.resolve('@semapps/activitypub/package.json'))) {
  const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
  if (version !== EXPECTED_VERSION) throw new Error(`Expected @semapps/activitypub@${EXPECTED_VERSION}, found ${version}`);
  const inboxFile = path.join(root, 'services/activitypub/subservices/inbox.js');
  const inboxResult = patchInbox(fs.readFileSync(inboxFile, 'utf8'));
  if (inboxResult.changed) fs.writeFileSync(inboxFile, inboxResult.source);
  const apiFile = path.join(root, 'services/activitypub/subservices/api.js');
  const apiResult = patchApi(fs.readFileSync(apiFile, 'utf8'));
  if (apiResult.changed) fs.writeFileSync(apiFile, apiResult.source);
  process.stdout.write('[ActivityPods] SemApps ActivityPub inbox actor identifier compatibility applied\n');
}

if (require.main === module) applyPatch();
module.exports = {
  EXPECTED_VERSION,
  MARKER,
  CHILD_META_UNSUPPORTED_MARKER,
  API_MARKER,
  PREVIOUS_API_MARKER,
  OLDER_API_MARKER,
  RAW_ACTOR_UNSUPPORTED_MARKER,
  SINGLETON_UNSUPPORTED_MARKER,
  PREVIOUS_MARKER,
  OLDER_MARKER,
  LEGACY_MARKER,
  PRISTINE_HASH,
  PRISTINE_API_HASH,
  PATCHED_API_HASH,
  PREVIOUS_PATCHED_API_HASH,
  OLDER_PATCHED_API_HASH,
  CHILD_META_UNSUPPORTED_PATCHED_HASH,
  RAW_ACTOR_UNSUPPORTED_PATCHED_HASH,
  SINGLETON_UNSUPPORTED_PATCHED_HASH,
  LEGACY_PATCHED_HASH,
  OLDER_PATCHED_HASH,
  PREVIOUS_PATCHED_HASH,
  PATCHED_HASH,
  sha256,
  patchInbox,
  patchApi,
  applyPatch
};
